#!/usr/bin/env python3

"""Validate an owner-only SaaS profile and create one ephemeral browser state file."""

import argparse
import datetime
import json
import os
import pathlib
import re
import stat
import urllib.parse


SCHEMA = "opnsense-openid-connect.live-config/v1"
ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
PROVIDERS = {"entra", "okta", "apple"}
TOP_FIELDS = {"schema", "profiles"}
PROFILE_FIELDS = {
    "issuer", "client_id", "client_secret", "provider_revision", "application_code", "scopes",
    "interaction", "username", "password", "manual_timeout_seconds", "public_inbound", "webgui_port",
}
PUBLIC_FIELDS = {"capabilities", "driver", "ssf_issuer", "ssf_audience", "ssf_push_secret"}
REVISION = re.compile(r"^(?:service:\d{4}-\d{2}-\d{2}|version:[A-Za-z0-9][A-Za-z0-9._+-]{0,111})$")
APPLICATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$")
SSF_PUSH_SECRET = re.compile(r"^[A-Za-z0-9_-]{43}$")
PUBLIC_CAPABILITIES = {"entra": {"back_logout"}, "okta": {"shared_signals"}, "apple": set()}


def load_config(path, provider):
    config_path = pathlib.Path(path)
    if not config_path.is_absolute() or not config_path.is_file() or config_path.is_symlink():
        raise ValueError("E2E_LIVE_CONFIG must name an absolute regular file")
    metadata = config_path.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("E2E_LIVE_CONFIG must be owned by the current user and mode 0600 or stricter")
    if config_path.resolve().is_relative_to(ROOT):
        raise ValueError("E2E_LIVE_CONFIG must stay outside the repository")
    try:
        document = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise ValueError("E2E_LIVE_CONFIG is not valid JSON") from error
    if not isinstance(document, dict) or set(document) != TOP_FIELDS or document.get("schema") != SCHEMA:
        raise ValueError("E2E_LIVE_CONFIG uses an unsupported or unsafe schema")
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not set(profiles) <= PROVIDERS or provider not in profiles:
        raise ValueError(f"E2E_LIVE_CONFIG has no {provider} profile")
    profile = profiles[provider]
    required = {"issuer", "client_id", "client_secret", "provider_revision", "application_code"}
    if not isinstance(profile, dict) or not required <= set(profile) <= PROFILE_FIELDS:
        raise ValueError(f"the {provider} live profile has missing or unknown fields")
    for field in ("issuer", "client_id", "client_secret", "provider_revision", "application_code"):
        if not isinstance(profile[field], str):
            raise ValueError(f"the live {field} must be a string")
    issuer = urllib.parse.urlsplit(profile["issuer"])
    if issuer.scheme != "https" or not issuer.hostname or issuer.fragment or issuer.query:
        raise ValueError("the live issuer must be an HTTPS URL without query or fragment")
    for field in ("client_id", "client_secret"):
        value = profile[field]
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ValueError(f"the live {field} must be a non-empty string")
    if not REVISION.fullmatch(profile["provider_revision"]) or not profile["provider_revision"].startswith("service:"):
        raise ValueError("a hosted live provider revision must be a service date")
    service_date = profile["provider_revision"].removeprefix("service:")
    try:
        parsed_service_date = datetime.date.fromisoformat(service_date)
        if parsed_service_date.isoformat() != service_date or parsed_service_date > datetime.date.today():
            raise ValueError
    except ValueError as error:
        raise ValueError("the live service revision must contain a real date") from error
    if not APPLICATION.fullmatch(profile["application_code"]):
        raise ValueError("the live application code is not URL-safe")
    interaction = profile.get("interaction", "manual")
    if interaction not in {"automatic", "manual"}:
        raise ValueError("live interaction must be automatic or manual")
    username = profile.get("username", "")
    password = profile.get("password", "")
    if (
        not isinstance(username, str) or not isinstance(password, str)
        or len(username) > 4096 or len(password) > 4096
    ):
        raise ValueError("live username and password must be bounded strings")
    if interaction == "automatic" and (not username or not password):
        raise ValueError("automatic live interaction needs username and password")
    manual_timeout = profile.get("manual_timeout_seconds", 600)
    if not isinstance(manual_timeout, int) or not 60 <= manual_timeout <= 1800:
        raise ValueError("manual live timeout must be between 60 and 1800 seconds")
    webgui_port = profile.get("webgui_port")
    if webgui_port is not None and (not isinstance(webgui_port, int) or not 1024 <= webgui_port <= 65535):
        raise ValueError("live WebGUI port must be between 1024 and 65535")
    scopes = profile.get("scopes", ["openid", "email", "profile"])
    if (
        not isinstance(scopes, list) or not scopes or len(scopes) > 16
        or any(not isinstance(scope, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", scope) for scope in scopes)
    ):
        raise ValueError("live scopes must be a short list of safe scope names")
    public = profile.get("public_inbound")
    if public is not None:
        if (
            not isinstance(public, dict) or not {"capabilities", "driver"} <= set(public)
            or not set(public) <= PUBLIC_FIELDS
        ):
            raise ValueError("public_inbound must name capabilities and an owner-only driver")
        capabilities = public["capabilities"]
        if (
            not isinstance(capabilities, list) or not capabilities
            or any(not isinstance(capability, str) for capability in capabilities)
            or not set(capabilities) <= PUBLIC_CAPABILITIES[provider]
        ):
            raise ValueError("public_inbound contains an unsupported capability")
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("public_inbound capabilities must be distinct")
        ssf_fields = {"ssf_issuer", "ssf_audience", "ssf_push_secret"}
        if "shared_signals" in capabilities:
            if not ssf_fields <= set(public):
                raise ValueError("Shared Signals live tests need issuer, audience and push secret")
            if not all(isinstance(public[field], str) for field in ssf_fields):
                raise ValueError("Shared Signals live settings must be strings")
            ssf_issuer = urllib.parse.urlsplit(public["ssf_issuer"])
            if ssf_issuer.scheme != "https" or not ssf_issuer.hostname or ssf_issuer.query or ssf_issuer.fragment:
                raise ValueError("the Shared Signals issuer must be a bounded HTTPS URL")
            if (
                not 1 <= len(public["ssf_audience"]) <= 256
                or not SSF_PUSH_SECRET.fullmatch(public["ssf_push_secret"])
            ):
                raise ValueError("Shared Signals audience is missing or the push secret is not 43-character base64url")
        elif set(public) & ssf_fields:
            raise ValueError("Shared Signals settings require the shared_signals capability")
        driver = pathlib.Path(public["driver"]) if isinstance(public.get("driver"), str) else pathlib.Path()
        if (
            not driver.is_absolute() or not driver.is_file() or driver.is_symlink()
            or driver.resolve().is_relative_to(ROOT)
        ):
            raise ValueError("the public_inbound driver must be an absolute regular file outside the repository")
        driver_metadata = driver.stat()
        if (
            driver_metadata.st_uid != os.getuid() or stat.S_IMODE(driver_metadata.st_mode) & 0o077
            or not stat.S_IMODE(driver_metadata.st_mode) & stat.S_IXUSR
        ):
            raise ValueError("the public_inbound driver must be owner-only and executable")
    return profile | {
        "scopes": scopes, "interaction": interaction, "username": username, "password": password,
        "manual_timeout_seconds": manual_timeout, "webgui_port": webgui_port,
    }


def state(profile, provider, opnsense_url, run_id):
    opnsense = urllib.parse.urlsplit(opnsense_url)
    if (
        opnsense.scheme != "https" or not opnsense.hostname or opnsense.path not in {"", "/"}
        or opnsense.query or opnsense.fragment
    ):
        raise ValueError("E2E_OPNSENSE_URL must be an HTTPS origin")
    opnsense_port = opnsense.port or 443
    if profile["webgui_port"] is not None and profile["webgui_port"] != opnsense_port:
        raise ValueError("E2E_OPNSENSE_URL does not use the registered live WebGUI port")
    callback = f"{opnsense_url.rstrip('/')}/api/openidconnect/auth/callback/{profile['application_code']}"
    return {
        "schema": 2,
        "provider": provider,
        "profile": provider,
        "source": "live",
        "cluster": os.environ.get("E2E_CLUSTER", "direct"),
        "run_id": run_id,
        "url": f"{urllib.parse.urlsplit(profile['issuer']).scheme}://{urllib.parse.urlsplit(profile['issuer']).netloc}",
        "authority": urllib.parse.urlsplit(profile["issuer"]).netloc,
        "issuer": profile["issuer"],
        "client_id": profile["client_id"],
        "client_secret": profile["client_secret"],
        "provider_revision": profile["provider_revision"],
        "application_code": profile["application_code"],
        "callback": callback,
        "server_name": f"{provider} live E2E {run_id}",
        "scopes": profile["scopes"],
        "interaction": profile["interaction"],
        "username": profile["username"],
        "password": profile["password"],
        "manual_timeout_seconds": profile["manual_timeout_seconds"],
        "webgui_port": profile["webgui_port"],
        "public_inbound": profile.get("public_inbound"),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--provider", required=True, choices=sorted(PROVIDERS))
    parser.add_argument("--opnsense-url")
    parser.add_argument("--run-id")
    parser.add_argument("--state")
    parser.add_argument("--print-web-port", action="store_true")
    arguments = parser.parse_args()
    try:
        profile = load_config(arguments.config, arguments.provider)
        if arguments.print_web_port:
            if profile["webgui_port"] is None:
                raise ValueError("local live tests require a stable webgui_port in E2E_LIVE_CONFIG")
            print(profile["webgui_port"])
            return
        if not arguments.opnsense_url or not arguments.run_id or not arguments.state:
            raise ValueError("state generation needs the OPNsense URL, run ID and output path")
        payload = state(profile, arguments.provider, arguments.opnsense_url, arguments.run_id)
    except ValueError as error:
        parser.error(str(error))
    output = pathlib.Path(arguments.state)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.chmod(0o600)


if __name__ == "__main__":
    main()
