#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Prepare and run a disposable amd64 OPNsense VM on an Apple Silicon Mac."""

import argparse
import base64
import bz2
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request


HERE = pathlib.Path(__file__).resolve().parent
TRUST_FILE = HERE / "vm" / "trust.json"
BOOTSTRAP_EXPECT = HERE / "vm" / "bootstrap.exp"
CACHE = pathlib.Path(os.environ.get(
    "E2E_VM_CACHE", pathlib.Path.home() / "Library" / "Caches" / "opnsense-openid-connect" / "e2e",
)).expanduser().resolve()
MIRROR = "https://pkg.opnsense.org/releases/mirror"
UTMCTL = pathlib.Path("/Applications/UTM.app/Contents/MacOS/utmctl")
VERSION = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")


def log(message):
    print(message, file=sys.stderr, flush=True)


def run(*arguments, capture=False, input_text=None, quiet=False, check=True):
    options = {"check": check, "text": True, "input": input_text}
    if capture:
        options["capture_output"] = True
    elif quiet:
        options.update({"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL})
    return subprocess.run(arguments, **options)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(mode)
    temporary.replace(path)


def download(url, destination, refresh=False):
    if destination.exists() and not refresh:
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.download")
    log(f"Downloading {url}")
    with urllib.request.urlopen(url, timeout=30) as response, temporary.open("wb") as output:
        shutil.copyfileobj(response, output, 1024 * 1024)
    temporary.replace(destination)
    return destination


def latest_release(trust):
    try:
        with urllib.request.urlopen(f"{MIRROR}/README", timeout=10) as response:
            readme = response.read().decode("utf-8")
        match = re.search(r"latest stable release image for OPNsense is ([0-9.]+)", readme)
        if match and VERSION.fullmatch(match.group(1)):
            return match.group(1)
    except (OSError, urllib.error.URLError):
        log("Release check unavailable; using the newest authenticated cached release.")
    cached = [path.name for path in (CACHE / "downloads").glob("*") if VERSION.fullmatch(path.name)]
    return max(cached, key=version_tuple) if cached else trust["release"]


def version_tuple(version):
    return tuple(int(part) for part in version.split("."))


def signature_bytes(signature_path):
    return base64.b64decode(signature_path.read_bytes(), validate=False)


def verify_signature(public_key, signature_path, payload_path):
    decoded = signature_path.with_suffix(f"{signature_path.suffix}.decoded")
    decoded.write_bytes(signature_bytes(signature_path))
    try:
        run(
            "openssl", "dgst", "-sha256", "-verify", str(public_key),
            "-signature", str(decoded), str(payload_path), quiet=True,
        )
    finally:
        decoded.unlink(missing_ok=True)


def authenticated_metadata(version, trust, refresh=False):
    directory = CACHE / "downloads" / version
    names = {
        "public_key": f"OPNsense-{version}.pub",
        "public_key_signature": f"OPNsense-{version}.pub.sig",
        "checksums": f"OPNsense-{version}-checksums-amd64.sha256",
        "checksums_signature": f"OPNsense-{version}-checksums-amd64.sha256.sig",
        "image_signature": f"OPNsense-{version}-nano-amd64.img.sig",
    }
    paths = {key: download(f"{MIRROR}/{name}", directory / name, refresh) for key, name in names.items()}
    if version == trust["release"]:
        if sha256(paths["public_key"]) != trust["public_key_sha256"]:
            raise RuntimeError("the release public key does not match the repository trust anchor")
    else:
        if version_tuple(version) <= version_tuple(trust["release"]):
            raise RuntimeError(f"release {version} predates the repository trust anchor")
        anchor = directory / f"OPNsense-{trust['release']}.trusted.pub"
        atomic_write(anchor, trust["public_key_pem"])
        try:
            verify_signature(anchor, paths["public_key_signature"], paths["public_key"])
        except subprocess.CalledProcessError as error:
            raise RuntimeError(
                f"OPNsense {version} cannot be chained to the {trust['release']} trust anchor; "
                "review and update tests/e2e/vm/trust.json"
            ) from error
    verify_signature(paths["public_key"], paths["checksums_signature"], paths["checksums"])
    image_name = f"OPNsense-{version}-nano-amd64.img.bz2"
    pattern = re.compile(rf"SHA256 \({re.escape(image_name)}\) = ([a-f0-9]{{64}})")
    match = pattern.search(paths["checksums"].read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError(f"the signed checksums do not contain {image_name}")
    if version == trust["release"] and match.group(1) != trust["compressed_sha256"]:
        raise RuntimeError("the signed image checksum does not match the repository trust anchor")
    return paths, image_name, match.group(1)


def qemu_img():
    executable = shutil.which("qemu-img")
    if not executable:
        raise RuntimeError("qemu-img is required to maintain compact disposable disks")
    return executable


def ensure_key():
    private_key = CACHE / "ssh" / "id_ed25519"
    if not private_key.exists():
        private_key.parent.mkdir(parents=True, exist_ok=True)
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "opnsense-oidc-e2e", "-f", str(private_key))
    private_key.chmod(0o600)
    return private_key


def prepare_image(refresh=False, backend="auto"):
    trust = json.loads(TRUST_FILE.read_text(encoding="utf-8"))
    version = latest_release(trust)
    paths, image_name, expected_hash = authenticated_metadata(version, trust, refresh)
    directory = CACHE / "images" / version
    compressed = directory / image_name
    download(f"{MIRROR}/{image_name}", compressed, refresh)
    if sha256(compressed) != expected_hash:
        raise RuntimeError(f"checksum mismatch for {compressed}")
    imported = directory / f"OPNsense-{version}-import.qcow2"
    if refresh or not imported.exists():
        raw = directory / f"OPNsense-{version}-nano-amd64.img"
        temporary_raw = raw.with_name(f".{raw.name}.{os.getpid()}.tmp")
        log(f"Decompressing and authenticating OPNsense {version}")
        with bz2.open(compressed, "rb") as source, temporary_raw.open("wb") as destination:
            shutil.copyfileobj(source, destination, 1024 * 1024)
        temporary_raw.replace(raw)
        verify_signature(paths["public_key"], paths["image_signature"], raw)
        temporary_qcow = imported.with_name(f".{imported.name}.{os.getpid()}.tmp")
        run(qemu_img(), "convert", "-f", "raw", "-O", "qcow2", str(raw), str(temporary_qcow))
        run(qemu_img(), "resize", str(temporary_qcow), "8G", quiet=True)
        temporary_qcow.replace(imported)
        raw.unlink(missing_ok=True)
    base = directory / f"OPNsense-{version}-e2e-base.qcow2"
    if refresh:
        base.unlink(missing_ok=True)
    if not base.exists():
        bootstrap_base(imported, base, backend)
    ensure_key()
    atomic_write(CACHE / "current.json", json.dumps({"version": version, "base": str(base)}, indent=2) + "\n")
    return version, base


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def available_backends():
    available = []
    if shutil.which("qemu-system-x86_64"):
        available.append("qemu")
    if UTMCTL.is_file() and shutil.which("osascript"):
        available.append("utm")
    return available


def choose_backend(requested):
    available = available_backends()
    if requested != "auto":
        if requested not in available:
            found = ", ".join(available) or "none"
            raise RuntimeError(f"requested backend {requested} is unavailable (found: {found})")
        return requested
    if not available:
        raise RuntimeError("neither Homebrew QEMU nor UTM is available")
    preference = CACHE / "backend.json"
    if preference.exists():
        selected = json.loads(preference.read_text(encoding="utf-8")).get("selected")
        if selected in available:
            return selected
    # Both variants use QEMU TCG for an amd64 guest on arm64. Direct QEMU avoids
    # the UTM frontend and automation boundary and is the faster default; an
    # explicit benchmark can replace this choice on a particular Mac.
    return "qemu" if "qemu" in available else available[0]


def network_arguments(web_port, ssh_port):
    return [
        "-netdev", "user,id=wan,net=10.0.2.0/24,dhcpstart=10.0.2.15",
        "-device", "virtio-net-pci,netdev=wan,mac=52:54:00:12:34:10",
        "-netdev", (
            "user,id=lan,net=192.168.1.0/24,dhcpstart=192.168.1.15,"
            f"hostfwd=tcp:127.0.0.1:{web_port}-192.168.1.1:443,"
            f"hostfwd=tcp:127.0.0.1:{ssh_port}-192.168.1.1:22"
        ),
        "-device", "virtio-net-pci,netdev=lan,mac=52:54:00:12:34:11",
    ]


def launch_qemu(disk, run_directory, web_port, ssh_port, serial_port):
    executable = shutil.which("qemu-system-x86_64")
    command = [
        executable, "-name", "OPNsense OIDC E2E", "-machine", "q35,accel=tcg,vmport=off",
        "-cpu", "max", "-smp", "2", "-m", "4096", "-display", "none", "-monitor", "none",
        "-drive", f"file={disk},if=virtio,format=qcow2,cache=writeback,discard=unmap",
        *network_arguments(web_port, ssh_port),
        "-chardev", f"socket,id=console,host=127.0.0.1,port={serial_port},server=on,wait=off",
        "-serial", "chardev:console",
    ]
    log_file = (run_directory / "qemu.log").open("ab")
    process = subprocess.Popen(command, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True)
    return {
        "backend": "qemu", "pid": process.pid, "serial_port": serial_port,
        "log_file": str(run_directory / "qemu.log"),
    }


def apple_script_argument(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def launch_utm(disk, run_directory, web_port, ssh_port, _serial_port):
    name = f"OPNsense OIDC E2E {run_directory.name}"
    # UTM's host-tuned Skylake model exposes instructions that make OpenSSH in
    # this cross-architecture FreeBSD guest fault. qemu64 is conservative and
    # materially faster here than UTM's one-core `max` model.
    arguments = ["-cpu", "qemu64", *network_arguments(web_port, ssh_port)]
    records = ", ".join(
        f'{{argument string:"{apple_script_argument(value)}"}}' for value in arguments
    )
    script = f'''
on run argv
  set diskPath to POSIX file (item 1 of argv)
  tell application "UTM"
    set extraArguments to {{{records}}}
    set newVM to make new virtual machine with properties {{backend:qemu, configuration:{{name:"{name}", ¬
      notes:"Disposable opnsense-openid-connect E2E VM", architecture:"x86_64", machine:"q35", ¬
      memory:4096, cpu cores:2, hypervisor:false, uefi:false, ¬
      drives:{{{{removable:false, interface:VirtIO, raw:false, source:diskPath}}}}, ¬
      network interfaces:{{}}, qemu additional arguments:extraArguments}}}}
    return id of newVM
  end tell
end run
'''
    result = run("osascript", "-", str(disk), capture=True, input_text=script)
    identifier = result.stdout.strip()
    imported = (
        pathlib.Path.home() / "Library" / "Containers" / "com.utmapp.UTM" / "Data" / "Documents"
        / f"{name}.utm" / "Data" / "disk.qcow2"
    )
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline and not imported.is_file():
        time.sleep(1)
    if not imported.is_file():
        run(str(UTMCTL), "delete", identifier, check=False, quiet=True)
        raise RuntimeError("UTM did not finish importing the disposable disk")
    try:
        run(str(UTMCTL), "start", identifier, "--hide", quiet=True)
    except subprocess.CalledProcessError:
        run(str(UTMCTL), "delete", identifier, check=False, quiet=True)
        raise
    serial_path = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        serial = run(str(UTMCTL), "attach", identifier, capture=True, check=False)
        match = re.search(r"PTTY:\s*(/dev/tty[^\s]+)", serial.stdout + serial.stderr)
        if match:
            serial_path = match.group(1)
            break
        time.sleep(1)
    if not serial_path:
        run(str(UTMCTL), "stop", identifier, "--force", check=False, quiet=True)
        run(str(UTMCTL), "delete", identifier, check=False, quiet=True)
        raise RuntimeError("UTM did not expose its serial console")
    return {
        "backend": "utm", "utm_id": identifier, "utm_name": name,
        "serial_path": serial_path, "serial_port": None,
    }


def launch(backend, disk, run_directory, web_port, ssh_port, serial_port):
    if backend == "qemu":
        return launch_qemu(disk, run_directory, web_port, ssh_port, serial_port)
    return launch_utm(disk, run_directory, web_port, ssh_port, serial_port)


def wait_tcp(port, timeout=900):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(2)
    raise RuntimeError(f"timed out waiting for loopback port {port}")


def bootstrap_payload(public_key):
    encoded_key = base64.b64encode((public_key.strip() + "\n").encode()).decode()
    php = (
        "<?php require_once('/usr/local/etc/inc/config.inc');"
        "require_once('/usr/local/etc/inc/util.inc');global $config;"
        "$config['interfaces']['wan']['if']='vtnet0';$config['interfaces']['wan']['ipaddr']='dhcp';"
        "$config['interfaces']['lan']['if']='vtnet1';$config['interfaces']['lan']['ipaddr']='192.168.1.1';"
        "$config['interfaces']['lan']['subnet']='24';$config['system']['ssh']['enabled']='enabled';"
        "$config['system']['ssh']['permitrootlogin']=true;$config['system']['ssh']['noauto']=1;"
        "$config['system']['webgui']['althostnames']='opnsense.opnsense.test';"
        "unset($config['trigger_initial_wizard']);"
        f"foreach($config['system']['user'] as &$user){{if(($user['name']??'')==='root'){{"
        f"$user['authorizedkeys']='{encoded_key}';}}}}"
        "unset($user);write_config('Prepared disposable OIDC E2E VM');"
    )
    encoded_php = base64.b64encode(php.encode()).decode()
    shell = f"""#!/bin/sh
set -eu
mkdir -p /root/.ssh
echo '{encoded_key}' | /usr/bin/base64 -d > /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys
echo '{encoded_php}' | /usr/bin/base64 -d > /tmp/opnsense-oidc-vm-bootstrap.php
/usr/local/bin/php /tmp/opnsense-oidc-vm-bootstrap.php
/usr/local/sbin/configctl openssh restart
echo OPNSENSE_OIDC_VM_BOOTSTRAP_OK
"""
    return base64.b64encode(shell.encode()).decode()


def stop_backend(state):
    if state.get("backend") == "qemu" and state.get("pid"):
        try:
            os.killpg(state["pid"], signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                os.kill(state["pid"], 0)
            except (ProcessLookupError, PermissionError):
                break
            time.sleep(0.5)
        else:
            try:
                os.killpg(state["pid"], signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
    elif state.get("backend") == "utm" and state.get("utm_id"):
        run(str(UTMCTL), "stop", state["utm_id"], "--request", check=False, quiet=True)
        time.sleep(3)
        run(str(UTMCTL), "stop", state["utm_id"], "--force", check=False, quiet=True)
        run(str(UTMCTL), "delete", state["utm_id"], check=False, quiet=True)


def bootstrap_base(imported, base, requested_backend):
    backend = choose_backend(requested_backend)
    key = ensure_key()
    public_key = key.with_suffix(".pub").read_text(encoding="utf-8")
    run_directory = CACHE / "runs" / f"bootstrap-{int(time.time())}-{os.getpid()}"
    run_directory.mkdir(parents=True)
    overlay = run_directory / "bootstrap.qcow2"
    run(qemu_img(), "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(imported), str(overlay))
    web_port, ssh_port, serial_port = free_port(), free_port(), free_port()
    state = launch(backend, overlay, run_directory, web_port, ssh_port, serial_port)
    try:
        log(f"Bootstrapping OPNsense through the {backend} serial console (first run only)")
        if backend == "qemu":
            wait_tcp(serial_port, 60)
            arguments = [str(BOOTSTRAP_EXPECT), "qemu", str(serial_port), bootstrap_payload(public_key)]
        else:
            arguments = [str(BOOTSTRAP_EXPECT), "utm", state["serial_path"], bootstrap_payload(public_key)]
        run(*arguments)
        if backend == "qemu":
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                try:
                    os.kill(state["pid"], 0)
                except ProcessLookupError:
                    break
                time.sleep(1)
        else:
            time.sleep(5)
        temporary = base.with_name(f".{base.name}.{os.getpid()}.tmp")
        run(qemu_img(), "convert", "-O", "qcow2", str(overlay), str(temporary))
        temporary.replace(base)
    finally:
        stop_backend(state)
        shutil.rmtree(run_directory, ignore_errors=True)


def write_ssh_config(run_directory, ssh_port):
    known_hosts = run_directory / "known_hosts"
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        scan = run("ssh-keyscan", "-T", "3", "-p", str(ssh_port), "127.0.0.1", capture=True, check=False)
        if scan.returncode == 0 and scan.stdout.strip():
            break
        time.sleep(3)
    else:
        raise RuntimeError("could not collect the disposable OPNsense SSH host key")
    atomic_write(known_hosts, scan.stdout)
    config = run_directory / "ssh_config"
    key = ensure_key()
    atomic_write(config, f"""Host opnsense-e2e
  HostName 127.0.0.1
  Port {ssh_port}
  User root
  IdentityFile {key}
  IdentitiesOnly yes
  BatchMode yes
  UserKnownHostsFile {known_hosts}
  StrictHostKeyChecking yes
""")
    return config


def start_vm(arguments):
    version, base = prepare_image(arguments.refresh, arguments.backend)
    backend = choose_backend(arguments.backend)
    run_directory = CACHE / "runs" / f"run-{int(time.time())}-{os.getpid()}"
    run_directory.mkdir(parents=True)
    overlay = run_directory / "disk.qcow2"
    if backend == "utm":
        # UTM imports external disks into its sandbox. A standalone qcow2 avoids
        # losing an absolute backing-file relationship during that copy.
        run(qemu_img(), "convert", "-O", "qcow2", str(base), str(overlay))
    else:
        run(qemu_img(), "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay))
    web_port = arguments.web_port or free_port()
    ssh_port, serial_port = free_port(), free_port()
    while ssh_port == web_port:
        ssh_port = free_port()
    while serial_port in {web_port, ssh_port}:
        serial_port = free_port()
    state = {
        **launch(backend, overlay, run_directory, web_port, ssh_port, serial_port),
        "version": version, "run_directory": str(run_directory), "disk": str(overlay),
        "web_port": web_port, "ssh_port": ssh_port,
    }
    state_path = run_directory / "state.json"
    try:
        log(f"Waiting for OPNsense {version} ({backend})")
        wait_tcp(ssh_port)
        config = write_ssh_config(run_directory, ssh_port)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            probe = run("ssh", "-F", str(config), "opnsense-e2e", "true", quiet=True, check=False)
            if probe.returncode == 0:
                break
            time.sleep(3)
        else:
            raise RuntimeError("OPNsense SSH did not accept the pinned test key")
        run(
            "ssh", "-F", str(config), "opnsense-e2e",
            "grep -q '[[:space:]]provider\\.opnsense\\.test' /etc/hosts || "
            "printf '10.0.2.2\\tprovider.opnsense.test\\n' >> /etc/hosts",
            quiet=True,
        )
        webgui_config = (
            "require_once('/usr/local/etc/inc/config.inc');require_once('/usr/local/etc/inc/util.inc');"
            "$config['system']['webgui']['althostnames']='opnsense.opnsense.test';"
            "unset($config['trigger_initial_wizard']);"
            "write_config('Prepared disposable OIDC E2E hostname');"
        )
        run(
            "ssh", "-F", str(config), "opnsense-e2e",
            f"/usr/local/bin/php -r {shlex.quote(webgui_config)}",
            quiet=True,
        )
        state["ssh_config"] = str(config)
        atomic_write(state_path, json.dumps(state, indent=2) + "\n")
        output = {
            "backend": backend, "version": version,
            "url": f"https://opnsense.opnsense.test:{web_port}",
            "ssh": "opnsense-e2e", "ssh_config": str(config), "state": str(state_path),
        }
        print(json.dumps(output))
    except (Exception, KeyboardInterrupt):
        stop_backend(state)
        shutil.rmtree(run_directory, ignore_errors=True)
        raise


def stop_vm(state_path, keep=False):
    state_path = pathlib.Path(state_path).resolve()
    state = json.loads(state_path.read_text(encoding="utf-8"))
    stop_backend(state)
    if not keep:
        run_directory = pathlib.Path(state["run_directory"]).resolve()
        if run_directory.parent == (CACHE / "runs").resolve():
            shutil.rmtree(run_directory, ignore_errors=True)


def status():
    current = CACHE / "current.json"
    result = {
        "cache": str(CACHE), "available_backends": available_backends(),
        "prepared": json.loads(current.read_text(encoding="utf-8")) if current.exists() else None,
    }
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--backend", choices=("auto", "qemu", "utm"), default="auto")
    prepare.add_argument("--refresh", action="store_true")
    start = subparsers.add_parser("start")
    start.add_argument("--backend", choices=("auto", "qemu", "utm"), default="auto")
    start.add_argument("--refresh", action="store_true")
    start.add_argument("--web-port", type=int, choices=range(1024, 65536))
    stop = subparsers.add_parser("stop")
    stop.add_argument("--state", required=True)
    stop.add_argument("--keep", action="store_true")
    subparsers.add_parser("status")
    arguments = parser.parse_args()
    if arguments.command == "prepare":
        version, base = prepare_image(arguments.refresh, arguments.backend)
        print(json.dumps({"version": version, "base": str(base)}))
    elif arguments.command == "start":
        start_vm(arguments)
    elif arguments.command == "stop":
        stop_vm(arguments.state, arguments.keep)
    else:
        status()


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        print(f"VM error: {error}", file=sys.stderr)
        raise SystemExit(1)
