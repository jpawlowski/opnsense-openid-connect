#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Expose only the two provider-to-OPNsense POST routes through a Quick Tunnel."""

import argparse
import ipaddress
import json
import os
import pathlib
import re
import socket
import subprocess
import time
import urllib.parse


HERE = pathlib.Path(__file__).resolve().parent
SAFE_RUN = re.compile(r"^[a-f0-9]{8}$")
# This is the same bounded URL-segment syntax accepted by live-config.py.
# Local runs still generate e2e-<run-id>; live tenants need stable registered
# application codes and must not be forced into that disposable namespace.
SAFE_APPLICATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$")
QUICK_TUNNEL = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def run(*arguments, capture=False, quiet=False):
    options = {"check": True, "text": True}
    if capture:
        options["capture_output"] = True
    if quiet:
        options.update({"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL})
    return subprocess.run(arguments, **options)


def image(name):
    return run(str(HERE / "providers" / "image.py"), name, capture=True).stdout.strip()


def write(path, content, mode=0o600):
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def proxy_host_arguments(hostname, address):
    if address == "":
        return []
    if address != "host-gateway":
        try:
            ipaddress.ip_address(address)
        except ValueError as error:
            raise ValueError("the public-inbound proxy address must be host-gateway or an IP address") from error
    return ["--add-host", f"{hostname}:{address}"]


def proxy_config(opnsense_url, authority, application):
    return f"""events {{}}
http {{
  access_log off;
  server_tokens off;
  limit_req_zone $binary_remote_addr zone=provider_callbacks:1m rate=5r/s;
  server {{
    listen 8080;
    client_max_body_size 128k;
    client_body_timeout 5s;
    proxy_connect_timeout 5s;
    proxy_read_timeout 10s;
    proxy_send_timeout 10s;
    location = /api/openidconnect/auth/backchannel/{application} {{
      limit_except POST {{ deny all; }}
      limit_req zone=provider_callbacks burst=10 nodelay;
      proxy_pass {opnsense_url};
      proxy_ssl_verify off;
      proxy_set_header Host {authority};
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header Authorization "";
    }}
    location = /api/openidconnect/ssf/push/{application} {{
      limit_except POST {{ deny all; }}
      limit_req zone=provider_callbacks burst=10 nodelay;
      proxy_pass {opnsense_url};
      proxy_ssl_verify off;
      proxy_set_header Host {authority};
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header Authorization $http_authorization;
    }}
    location / {{ return 404; }}
  }}
}}
"""


def start(arguments):
    if not SAFE_RUN.fullmatch(arguments.run_id) or not SAFE_APPLICATION.fullmatch(arguments.application_code):
        raise SystemExit("unsafe public-inbound run or application identifier")
    target = urllib.parse.urlsplit(arguments.opnsense_url)
    if target.scheme != "https" or not target.hostname or target.path not in {"", "/"}:
        raise SystemExit("the public-inbound target must be an HTTPS origin")
    work = pathlib.Path(arguments.work_dir).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    prefix = f"opnsense-oidc-inbound-{arguments.run_id}"
    network = prefix
    proxy = f"{prefix}-proxy"
    tunnel = f"{prefix}-cloudflared"
    authority = target.netloc
    application = arguments.application_code
    try:
        target_arguments = proxy_host_arguments(target.hostname, arguments.target_address)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    config = proxy_config(arguments.opnsense_url, authority, application)
    config_path = work / "public-inbound-nginx.conf"
    write(config_path, config, 0o644)
    run("docker", "network", "create", network, quiet=True)
    containers = []
    try:
        run(
            "docker", "run", "-d", "--name", proxy, "--network", network,
            *target_arguments,
            "-v", f"{config_path}:/etc/nginx/nginx.conf:ro",
            image("nginx"), quiet=True,
        )
        containers.append(proxy)
        run(
            "docker", "run", "-d", "--name", tunnel, "--network", network,
            image("cloudflared"), "tunnel", "--no-autoupdate", "--url", f"http://{proxy}:8080",
            quiet=True,
        )
        containers.append(tunnel)
        public_origin = ""
        for _ in range(90):
            logged = run("docker", "logs", tunnel, capture=True)
            logs = logged.stdout + logged.stderr
            match = QUICK_TUNNEL.search(logs)
            if match:
                candidate = match.group(0)
                try:
                    socket.getaddrinfo(urllib.parse.urlsplit(candidate).hostname, 443)
                except socket.gaierror:
                    # Quick Tunnel occasionally logs its random name before the
                    # corresponding public DNS record is visible to the runner.
                    pass
                else:
                    public_origin = candidate
                    break
            inspect = run("docker", "inspect", "-f", "{{.State.Running}}", tunnel, capture=True).stdout.strip()
            if inspect != "true":
                raise RuntimeError("cloudflared stopped before publishing a Quick Tunnel URL")
            time.sleep(1)
        if not public_origin:
            raise RuntimeError("cloudflared did not publish a resolvable Quick Tunnel URL within 90 seconds")
        state = {
            "schema": 1,
            "run_id": arguments.run_id,
            "application_code": application,
            "network": network,
            "containers": containers,
            "public_origin": public_origin,
        }
        write(pathlib.Path(arguments.state), json.dumps(state, indent=2, sort_keys=True) + "\n")
    except BaseException:
        for container in reversed(containers):
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    print(public_origin)


def stop(arguments):
    state_path = pathlib.Path(arguments.state)
    if not state_path.is_file():
        return
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if not SAFE_RUN.fullmatch(state.get("run_id", "")):
        raise SystemExit("refusing public-inbound cleanup for an unsafe state file")
    prefix = f"opnsense-oidc-inbound-{state['run_id']}"
    for container in reversed(state.get("containers", [])):
        if container.startswith(prefix):
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if state.get("network") == prefix:
        subprocess.run(["docker", "network", "rm", prefix], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("start")
    create.add_argument("--run-id", required=True)
    create.add_argument("--application-code", required=True)
    create.add_argument("--opnsense-url", required=True)
    create.add_argument("--target-address", default=os.environ.get("E2E_OPNSENSE_PROXY_ADDRESS", ""))
    create.add_argument("--work-dir", required=True)
    create.add_argument("--state", required=True)
    remove = commands.add_parser("stop")
    remove.add_argument("--state", required=True)
    arguments = parser.parse_args()
    (start if arguments.command == "start" else stop)(arguments)


if __name__ == "__main__":
    main()
