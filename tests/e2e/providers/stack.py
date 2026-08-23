#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Create the disposable, TLS-correct provider stacks used by browser E2E."""

import argparse
import json
import os
import pathlib
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


HERE = pathlib.Path(__file__).resolve().parent
SAFE_ID = re.compile(r"^[a-f0-9]{8}$")
PROVIDERS = {"authentik", "authelia", "pocketid"}


def run(*arguments, capture=False, quiet=False):
    options = {"check": True, "capture_output": capture, "text": True}
    if quiet:
        options.update({"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL})
    return subprocess.run(arguments, **options)


def write(path, content, mode=0o600):
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)


def image(name, canary=False):
    arguments = [str(HERE / "image.py"), name]
    if canary:
        arguments.append("--canary")
    return run(*arguments, capture=True).stdout.strip()


def bcrypt(password):
    output = run("htpasswd", "-bnBC", "10", "", password, capture=True).stdout.strip()
    return output.split(":", 1)[1].replace("$2y$", "$2a$")


def docker_run(name, network, image_reference, *arguments, environment=None, volumes=None, command=None):
    command_line = [
        "docker", "run", "-d", "--name", name, "--network", network,
        "--add-host", f"{os.environ['E2E_OPNSENSE_HOST']}:host-gateway",
    ]
    for key, value in sorted((environment or {}).items()):
        command_line.extend(["-e", f"{key}={value}"])
    for source, target, options in volumes or []:
        command_line.extend(["-v", f"{source}:{target}:{options}"])
    command_line.extend(arguments)
    command_line.append(image_reference)
    command_line.extend(command or [])
    run(*command_line, quiet=True)


def create_certificate(work, host):
    san = f"IP:{host}" if re.fullmatch(r"[0-9.]+", host) else f"DNS:{host}"
    run(
        "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "2",
        "-subj", "/CN=OPNsense OIDC provider E2E", "-keyout", str(work / "ca.key"),
        "-out", str(work / "ca.crt"), quiet=True,
    )
    run(
        "openssl", "req", "-newkey", "rsa:3072", "-nodes", "-subj", f"/CN={host}",
        "-addext", f"subjectAltName={san}", "-keyout", str(work / "server.key"),
        "-out", str(work / "server.csr"), quiet=True,
    )
    run(
        "openssl", "x509", "-req", "-days", "2", "-in", str(work / "server.csr"),
        "-CA", str(work / "ca.crt"), "-CAkey", str(work / "ca.key"), "-CAcreateserial",
        "-copy_extensions", "copy", "-out", str(work / "server.crt"), quiet=True,
    )


def start_authentik(state, canary):
    work = pathlib.Path(state["work_dir"])
    prefix = state["prefix"]
    network = state["network"]
    provider_image = image("authentik", canary)
    postgres_image = image("postgres")
    database = f"{prefix}-postgres"
    server = f"{prefix}-authentik"
    worker = f"{prefix}-worker"
    database_environment = {
        "POSTGRES_DB": "authentik", "POSTGRES_USER": "authentik",
        "POSTGRES_PASSWORD": state["database_password"],
    }
    docker_run(database, network, postgres_image, environment=database_environment)
    shared = {
        "AUTHENTIK_SECRET_KEY": state["service_secret"],
        "AUTHENTIK_POSTGRESQL__HOST": database,
        "AUTHENTIK_POSTGRESQL__NAME": "authentik",
        "AUTHENTIK_POSTGRESQL__USER": "authentik",
        "AUTHENTIK_POSTGRESQL__PASSWORD": state["database_password"],
        "AUTHENTIK_ERROR_REPORTING__ENABLED": "false",
        "AUTHENTIK_BOOTSTRAP_PASSWORD": state["password"],
        "AUTHENTIK_BOOTSTRAP_TOKEN": state["admin_token"],
    }
    volumes = [(str(work / "ca.crt"), "/etc/ssl/certs/opnsense-e2e-ca.crt", "ro")]
    docker_run(server, network, provider_image, environment=shared, volumes=volumes, command=["server"])
    docker_run(worker, network, provider_image, environment=shared, volumes=volumes, command=["worker"])
    state["upstream"] = f"http://{server}:9000"
    state["readiness"] = "/-/health/ready/"
    state["containers"].extend([database, server, worker])


def start_authelia(state, canary):
    work = pathlib.Path(state["work_dir"])
    name = f"{state['prefix']}-authelia"
    issuer = state["url"]
    password_hash = bcrypt(state["password"])
    client_hash = bcrypt(state["client_secret"])
    run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072",
        "-out", str(work / "oidc.key"), quiet=True)
    write(work / "users.yml", (
        f"users:\n  {state['username']}:\n    displayname: OIDC E2E\n"
        f"    password: '{password_hash}'\n    email: {state['username']}@example.com\n"
        "    groups: [admins]\n"
    ))
    private_key = (work / "oidc.key").read_text(encoding="utf-8").rstrip().replace("\n", "\n          ")
    config = f"""server:
  address: tcp://0.0.0.0:9091
log:
  level: info
identity_validation:
  reset_password:
    jwt_secret: {state['service_secret']}
authentication_backend:
  file:
    path: /config/users.yml
access_control:
  default_policy: one_factor
session:
  secret: {state['session_secret']}
  cookies:
    - name: authelia_session
      domain: {state['host']}
      authelia_url: {issuer}
storage:
  encryption_key: {state['storage_secret']}
  local:
    path: /config/db.sqlite3
notifier:
  filesystem:
    filename: /config/notification.txt
identity_providers:
  oidc:
    hmac_secret: {state['oidc_secret']}
    jwks:
      - key_id: e2e
        algorithm: RS256
        use: sig
        key: |
          {private_key}
    clients:
      - client_id: {state['client_id']}
        client_name: OPNsense E2E
        client_secret: '{client_hash}'
        public: false
        authorization_policy: one_factor
        redirect_uris:
          - {state['callback']}
        scopes: [openid, profile, email, groups]
        response_types: [code]
        grant_types: [authorization_code]
        token_endpoint_auth_method: client_secret_basic
        require_pkce: true
        pkce_challenge_method: S256
"""
    write(work / "configuration.yml", config)
    volumes = [(str(work), "/config", "rw")]
    docker_run(
        name, state["network"], image("authelia", canary),
        environment={"X_AUTHELIA_CONFIG": "/config/configuration.yml"}, volumes=volumes,
    )
    state["upstream"] = f"http://{name}:9091"
    state["readiness"] = "/api/health"
    state["issuer"] = issuer
    state["containers"].append(name)


def start_pocketid(state, canary):
    work = pathlib.Path(state["work_dir"])
    name = f"{state['prefix']}-pocketid"
    environment = {
        "APP_URL": state["url"], "TRUST_PROXY": "true", "STATIC_API_KEY": state["admin_token"],
        "ENCRYPTION_KEY": state["service_secret"], "VERSION_CHECK_DISABLED": "true",
    }
    volumes = [(str(work / "pocket-data"), "/app/data", "rw")]
    (work / "pocket-data").mkdir(mode=0o700)
    docker_run(name, state["network"], image("pocketid", canary), environment=environment, volumes=volumes)
    state["upstream"] = f"http://{name}:1411"
    state["readiness"] = "/.well-known/openid-configuration"
    state["issuer"] = state["url"]
    state["containers"].append(name)


def start_proxy(state):
    work = pathlib.Path(state["work_dir"])
    name = f"{state['prefix']}-tls"
    config = f"""events {{}}
http {{
  server {{
    listen 8443 ssl;
    ssl_certificate /tls/server.crt;
    ssl_certificate_key /tls/server.key;
    client_max_body_size 4m;
    location / {{
      proxy_pass {state['upstream']};
      proxy_http_version 1.1;
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-Host $http_host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $connection_upgrade;
    }}
  }}
}}
"""
    # nginx needs a map before connection_upgrade can be referenced.
    config = config.replace(
        "http {\n", "http {\n  map $http_upgrade $connection_upgrade { default upgrade; '' close; }\n",
    )
    write(work / "nginx.conf", config, 0o644)
    volumes = [
        (str(work / "nginx.conf"), "/etc/nginx/nginx.conf", "ro"),
        (str(work / "server.crt"), "/tls/server.crt", "ro"),
        (str(work / "server.key"), "/tls/server.key", "ro"),
    ]
    # OPNsense reaches the Mac through QEMU's 10.0.2.2 host gateway, which is
    # not a loopback connection. The per-run TLS name and random credentials
    # still prevent this disposable service from becoming a reusable endpoint.
    docker_run(name, state["network"], image("nginx"), "-p", f"{state['port']}:8443", volumes=volumes)
    state["containers"].append(name)


def wait_ready(state):
    host_header = state["authority"]
    probe = f"https://127.0.0.1:{state['port']}{state['readiness']}"
    context = __import__("ssl")._create_unverified_context()
    for _ in range(180):
        request = urllib.request.Request(probe, headers={"Host": host_header})
        try:
            with urllib.request.urlopen(request, timeout=2, context=context) as response:
                if response.status >= 500:
                    continue
            if state["provider"] == "authentik":
                admin = urllib.request.Request(
                    f"https://127.0.0.1:{state['port']}/api/v3/flows/instances/"
                    "?search=default-provider-authorization-implicit-consent",
                    headers={"Host": host_header, "Authorization": f"Bearer {state['admin_token']}"},
                )
                with urllib.request.urlopen(admin, timeout=2, context=context) as response:
                    flows = json.load(response)
                    if response.status != 200 or not flows.get("results"):
                        continue
            return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise SystemExit(f"provider {state['provider']} did not become ready; inspect {state['work_dir']}")


def start(arguments):
    if arguments.provider not in PROVIDERS or not SAFE_ID.fullmatch(arguments.run_id):
        raise SystemExit("unsafe provider or run identifier")
    work = pathlib.Path(arguments.work_dir).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    provider_url = urllib.parse.urlsplit(arguments.url)
    if provider_url.scheme != "https" or not provider_url.hostname or not provider_url.port:
        raise SystemExit("provider URL must be an explicit HTTPS origin with a port")
    state = {
        "schema": 1, "provider": arguments.provider, "profile": arguments.provider,
        "run_id": arguments.run_id, "work_dir": str(work), "url": arguments.url.rstrip("/"),
        "host": provider_url.hostname, "port": provider_url.port, "authority": provider_url.netloc,
        "prefix": f"opnsense-oidc-{arguments.provider}-{arguments.run_id}",
        "network": f"opnsense-oidc-{arguments.run_id}", "containers": [],
        "username": os.environ["E2E_TEST_USERNAME"], "password": os.environ["E2E_TEST_PASSWORD"],
        "client_id": os.environ["E2E_CLIENT_ID"], "client_secret": os.environ["E2E_CLIENT_SECRET"],
        "application_code": os.environ["E2E_APPLICATION_CODE"], "server_name": os.environ["E2E_SERVER_NAME"],
        "callback": os.environ["E2E_CALLBACK_URL"], "admin_token": os.environ["E2E_ADMIN_TOKEN"],
        "database_password": os.environ["E2E_DATABASE_PASSWORD"],
        "service_secret": os.environ["E2E_SERVICE_SECRET"],
        "session_secret": os.environ["E2E_SESSION_SECRET"],
        "storage_secret": os.environ["E2E_STORAGE_SECRET"],
        "oidc_secret": os.environ["E2E_OIDC_SECRET"],
        "capabilities": json.loads(run(str(HERE / "image.py"), arguments.provider, "--metadata", capture=True).stdout)[
            "capabilities"
        ],
    }
    create_certificate(work, state["host"])
    run("docker", "network", "create", state["network"])
    try:
        globals()[f"start_{arguments.provider}"](state, arguments.canary)
        start_proxy(state)
        wait_ready(state)
    except Exception:
        for container in reversed(state["containers"]):
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", state["network"]], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        raise
    write(pathlib.Path(arguments.state), json.dumps(state, indent=2, sort_keys=True) + "\n")


def stop(arguments):
    state_path = pathlib.Path(arguments.state)
    if not state_path.is_file():
        return
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if not SAFE_ID.fullmatch(state.get("run_id", "")):
        raise SystemExit("refusing cleanup for an unsafe state file")
    for container in reversed(state.get("containers", [])):
        if container.startswith("opnsense-oidc-"):
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    network = state.get("network", "")
    if network == f"opnsense-oidc-{state['run_id']}":
        subprocess.run(["docker", "network", "rm", network], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser("start")
    create.add_argument("--provider", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--url", required=True)
    create.add_argument("--work-dir", required=True)
    create.add_argument("--state", required=True)
    create.add_argument("--canary", action="store_true")
    remove = subparsers.add_parser("stop")
    remove.add_argument("--state", required=True)
    arguments = parser.parse_args()
    (start if arguments.command == "start" else stop)(arguments)


if __name__ == "__main__":
    main()
