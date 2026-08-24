#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

"""Checks the package that build.py produces, and the hygiene of what goes into it.

Two kinds of check live here:

  * the shape of the archive - `pkg` will not tell us it is wrong until someone tries to
    install it, and by then it is on a firewall
  * what the files may and may not contain - a licence notice on everything of ours, no
    German, and none of the naming, addresses or hosts of whoever built it

The second kind exists because this package is meant to be handed to strangers.
"""
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD = ROOT / "packaging" / "build.py"
VERSION = "0.0.0.test"

REQUIRED_KEYS = [
    "name", "origin", "version", "comment", "desc", "maintainer",
    "www", "abi", "arch", "prefix", "flatsize", "categories", "licenselogic",
    "licenses", "annotations",
]

EXECUTABLES = {
    "/usr/local/sbin/openid-connect-refresh",
    "/usr/local/sbin/openid-connect-watch",
}

# Nothing here names anything of the builder's, on purpose: a check written as a list of
# the names to keep out is itself a list of those names, published with the package. So it
# tests properties instead - and catches whatever a future author leaves behind, not only
# what this one thought of.
#
# An address literal has no business in this package at all - but only where it is used
# as one. A dotted quad in prose is usually a section number ("OIDC Core 3.1.2.1"), so a
# match counts only when it sits where a machine would: in quotes, behind a scheme, or in
# front of a port or a path.
ADDRESS = re.compile(
    r"""(?:(?<=//)|(?<=['"])|(?<=@))(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"""
    r"""|(?P<ip2>(?:\d{1,3}\.){3}\d{1,3})(?=[:/]|['"])"""
)
# The loopback the watchdog probes, and the ranges RFC 5737 reserves so that writing can
# show an address without meaning one.
ADDRESSES_ALLOWED = re.compile(
    r"^(?:127\.0\.0\.1"
    r"|192\.0\.2\.\d{1,3}"
    r"|198\.51\.100\.\d{1,3}"
    r"|203\.0\.113\.\d{1,3})$"
)

IS_ADDRESS = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

# A bare word with a dot in it is indistinguishable from code (input.value, core.digest),
# so hosts are read only where a host actually belongs: behind a scheme, or after an @.
URL_HOST = re.compile(r"https?://([a-z0-9._-]*)", re.I)
# RFC 2606 and RFC 6761 keep these reserved precisely so that writing does not have to
# borrow somebody's real name.
EXAMPLE_HOST = re.compile(r"(^|\.)(example\.(com|net|org)|example|invalid|test|localhost)$", re.I)
PROTOCOL_HOSTS = {
    "schemas.openid.net", "goauthentik.io", "version-2026-8.goauthentik.io",
    # XML namespace carried by the package-owned SVG provider marks.
    "www.w3.org",
    # Public issuers and useful public-service defaults used by named provider profiles.
    # `login` is the prefix the deliberately literal Microsoft issuer regex looks like
    # to URL_HOST.
    "login", "login.microsoftonline.com", "accounts.google.com",
    "appleid.apple.com", "www.linkedin.com", "slack.com",
    "api.login.yahoo.com", "orcid.org", "gitlab.com",
    # Standards-profile identifier used as an authentication context, not a builder host.
    "refeds.org",
    # Prefixes captured before a {region} placeholder, not complete hostnames.
    "cognito-idp.", "oauth.id.",
}

MAIL = re.compile(r"\b[a-z0-9._%%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)

# Words common enough in German to catch a stray sentence, rare enough in English
# and in code not to fire on their own.
GERMAN = r"\b(der|die|das|und|nicht|wird|werden|eine|einen|damit|dass|aber|kein|keine|" \
         r"oder|wenn|schon|noch|sich|auch|von|zum|zur|fuer|ueber|ohne|steht|liegt|" \
         r"Fassung|Datei|Paket|Anmeldung|Sitzung|Ursprung)\b"

failures = []
passed = 0
COPYRIGHT = ""


def notice():
    """The copyright line every file of ours has to carry, read from the licence.

    Taken from there rather than written out here, so that the name lives in one place and
    this check has no opinion about who wrote the thing.
    """
    for line in (ROOT / "LICENSE").read_text().splitlines():
        if line.startswith("Copyright"):
            holder = line.split(",", 1)[1].strip() if "," in line else line
            year = re.search(r"\b(\d{4})\b", line)
            return f"Copyright (C) {year.group(1)} {holder}" if year else None

    return None


def check(what, actual, expected=True, detail=""):
    """Compares and reports. Passing only `actual` asserts that it is true."""
    global passed
    if actual == expected:
        passed += 1
        print(f"  ok    {what}")
        return

    failures.append(what)
    print(f"  FAIL  {what}")
    print(f"        expected {expected!r}")
    print(f"        got      {actual!r}")
    if detail:
        print(f"        {detail}")


def group(name):
    print(f"\n{name}")


def load_build():
    """build.py, to ask it things rather than only to run it."""
    spec = importlib.util.spec_from_file_location("build", BUILD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def build():
    out = subprocess.run([sys.executable, str(BUILD), "--version", VERSION],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"the build itself failed:\n{out.stdout}\n{out.stderr}")

    return ROOT / "packaging" / "dist" / f"os-openid-connect-{VERSION}.pkg"


def main():
    global COPYRIGHT
    COPYRIGHT = notice()
    if COPYRIGHT is None:
        sys.exit("LICENSE carries no copyright line to check the sources against")

    group("A version pkg can carry")
    build_py = load_build()
    check("a release tag", build_py.pkg_version("v1.2.3"), "1.2.3")
    # a hyphen is what pkg reads as the end of a package's name, so `pkg query
    # %n-%v` and the watchdog that uses it would answer nonsense
    check("a pre-release tag", build_py.pkg_version("v1.0.0-beta1"), "1.0.0.beta1")
    check("work in progress", build_py.pkg_version("v1.0.0-3-gabc1234"), "1.0.0.3.gabc1234")
    check("a dirty tree", build_py.pkg_version("v1.0.0-dirty"), "1.0.0.dirty")
    check(
        "nothing that would be read as a name boundary survives",
        [v for v in ("v1.0.0-beta1", "v1.0.0-3-gabc1234") if "-" in build_py.pkg_version(v)],
        [],
    )

    package = build()

    group("The archive is shaped the way pkg expects")
    with tarfile.open(package) as archive:
        names = archive.getnames()
        members = {m.name: m for m in archive.getmembers()}
        manifest = json.loads(archive.extractfile("+MANIFEST").read())
        compact = json.loads(archive.extractfile("+COMPACT_MANIFEST").read())
        contents = {n: archive.extractfile(n).read() for n in names if not n.startswith("+")}

    check("the compact manifest comes first", names[0], "+COMPACT_MANIFEST")
    check("the full manifest comes second", names[1], "+MANIFEST")
    check("every other entry is an absolute path",
          [n for n in names[2:] if not n.startswith("/")], [])
    check("the compact manifest carries no file list", "files" not in compact)
    check("the full manifest carries one", "files" in manifest)

    group("The manifest says what it must")
    for key in REQUIRED_KEYS:
        check(f"it states {key}", key in manifest and manifest[key] != "")
    check("the version is the one asked for", manifest["version"], VERSION)
    check("nothing is tied to an architecture", (manifest["abi"], manifest["arch"]), ("*", "*"))
    check("it names its licence", manifest["annotations"].get("license"), "BSD-2-Clause")
    check("pkg sees one native licence", manifest.get("licenselogic"), "single")
    check("pkg sees the BSD two-clause licence", manifest.get("licenses"), ["BSD2CLAUSE"])
    check("it records the runtime cryptography provider",
          manifest["annotations"].get("runtime_crypto"), "OPNsense phpseclib3")
    check("it identifies the source revision honestly",
          bool(re.fullmatch(r"(?:[0-9a-f]{40}|unknown)(?:\.dirty)?",
                            manifest["annotations"].get("built_from", ""))), True)
    check("it bundles no third-party OIDC client",
          "bundled_library" not in manifest["annotations"])

    group("Every file is accounted for")
    listed = set(manifest["files"])
    shipped = set(contents)
    check("the manifest lists exactly what is in the archive", listed, shipped,
          f"only in manifest: {listed - shipped}; only in archive: {shipped - listed}")
    mismatched = [p for p, s in manifest["files"].items()
                  if s != "1$" + hashlib.sha256(contents[p]).hexdigest()]
    check("every checksum matches its file", mismatched, [])
    check("the flatsize is the sum of the files",
          manifest["flatsize"], sum(len(b) for b in contents.values()))

    group("Permissions and ownership")
    check("everything belongs to root:wheel",
          {(m.uname, m.gname) for n, m in members.items() if not n.startswith("+")},
          {("root", "wheel")})
    wrong_mode = [n for n, m in members.items()
                  if not n.startswith("+")
                  and m.mode != (0o755 if n in EXECUTABLES else 0o644)]
    check("scripts are executable and nothing else is", wrong_mode, [])

    group("The nightly run, and what is left behind when it goes")
    check("the watchdog is installed", "/usr/local/sbin/openid-connect-watch" in contents)
    check("the provider refresh worker is installed", "/usr/local/sbin/openid-connect-refresh" in contents)
    check("and something starts it", "/usr/local/etc/cron.d/openid-connect.cron" in contents)
    cron = contents.get("/usr/local/etc/cron.d/openid-connect.cron", b"").decode()
    check("nightly, as root, saying nothing when there is nothing to say",
          "root\t/usr/local/sbin/openid-connect-watch --check >/dev/null 2>&1" in cron)
    check("provider recovery runs every minute outside the browser path",
          "*\t*\t*\t*\t*\troot\t/usr/bin/lockf -t 0 /var/run/openid-connect-refresh.lock "
          "/usr/local/sbin/openid-connect-refresh >/dev/null 2>&1" in cron)
    check("it does not rely on periodic, which nothing in OPNsense uses",
          [n for n in contents if "/periodic/" in n], [])
    # pkg removes what it installed; the anchor is written at runtime under /var/db
    # and would otherwise outlive the package
    install = manifest.get("scripts", {}).get("post-install", "")
    deinstall = manifest.get("scripts", {}).get("post-deinstall", "")
    check("installing invalidates core's pluggable ACL cache",
          "/var/lib/php/tmp/opnsense_acl_cache.json" in install)
    check("uninstalling invalidates core's pluggable ACL cache",
          "/var/lib/php/tmp/opnsense_acl_cache.json" in deinstall)
    check("uninstalling takes the watchdog's anchor with it",
          "/var/db/openid-connect" in deinstall)
    check("uninstalling takes provider cache and circuit state with it",
          "/var/db/openid-connect/cache /var/db/openid-connect/runtime" in deinstall)
    check("uninstalling takes the OIDC session index with it",
          "/var/lib/php/sessions/.openidconnect-sessions" in deinstall)
    check("uninstalling takes the logout replay index with it",
          "/var/lib/php/sessions/.openidconnect-logout-tokens" in deinstall)
    check("uninstalling takes the Shared Signals replay index with it",
          "/var/lib/php/sessions/.openidconnect-security-events" in deinstall)
    check("uninstalling takes the form-post transaction index with it",
          "/var/lib/php/sessions/.openidconnect-transactions" in deinstall)
    check("uninstalling takes pending identity hints with it",
          "/var/lib/php/sessions/.openidconnect-pending-identities" in deinstall)
    check("but an upgrade keeps it", "PKG_UPGRADE" in deinstall)

    group("What ships with it")
    check("no Jumbojett library or licence is included",
          [n for n in contents if n.endswith(("OpenIDConnectClient.php", "LICENSE.jumbojett"))], [])
    check("no documentation is installed onto the firewall",
          [n for n in contents if n.endswith(".md")], [])
    provider_icons = {
        pathlib.PurePosixPath(n).name
        for n in contents
        if "/OPNsense/OpenIDConnect/assets/provider-icons/" in n and n.endswith(".svg")
    }
    check("every provider profile has one package-owned icon", provider_icons, {
        "apple.svg", "auth0.svg", "authentik.svg", "authelia.svg", "cognito.svg",
        "dex.svg", "duo.svg", "entra.svg", "fusionauth.svg", "general.svg", "gitlab.svg",
        "google.svg", "ibm_verify.svg", "jumpcloud.svg", "keycloak.svg",
        "linkedin.svg", "okta.svg", "onelogin.svg", "oracle_idcs.svg", "orcid.svg",
        "ping.svg", "pocketid.svg", "slack.svg", "wso2.svg", "yahoo.svg",
        "zitadel.svg",
    })
    unsafe_icons = []
    for name in sorted(n for n in contents if n.endswith(".svg")):
        svg = contents[name].decode("utf-8", "replace")
        if (len(contents[name]) > 262144 or "<svg" not in svg.lower() or re.search(
            r"<(?:script|foreignObject|iframe|object|embed)\b|\bon[a-z]+\s*=|"
            r"(?:href|src)\s*=\s*['\"]\s*(?:https?:|//)|"
            r"url\s*\(\s*['\"]?\s*(?:https?:|//)", svg, re.I
        )):
            unsafe_icons.append(name)
    check("package-owned SVG icons are small and self-contained", unsafe_icons, [])
    # the os- name is what puts it on the firmware page; a version file would
    # additionally register it in system.firmware.plugins, and every plugin sync
    # would then try to pkg install it out of a repository that does not have it
    check("it is named so the firmware page lists it", manifest["name"].startswith("os-"))
    check("but registers itself nowhere",
          [n for n in contents if "/opnsense/version/" in n], [])
    check("and is not something autoremove may take", manifest.get("automatic"), False)

    group("No address, host or mailbox of the builder's travels along")
    declared = URL_HOST.findall(manifest["www"])
    declared_host = declared[0].split(":")[0] if declared else ""
    declared_mail = manifest["maintainer"]
    check("the manifest declares where the package comes from", declared_host != "")

    for name, blob in sorted(contents.items()):
        text = blob.decode("utf-8", "replace")
        short = pathlib.Path(name).name

        found = {m.group("ip") or m.group("ip2") for m in ADDRESS.finditer(text)}
        stray = sorted(a for a in found if not ADDRESSES_ALLOWED.match(a))
        check(f"{short} names no address", stray, [])

        # every host that appears has to be the one the manifest already admits to, or a
        # name reserved for documentation - anything else is somebody's real machine
        seen = set(URL_HOST.findall(text)) | {m.split("@", 1)[1] for m in MAIL.findall(text)}
        hosts = sorted({h.split(":")[0].lower() for h in seen if h}
                       - {declared_host.lower()})
        # an address that turns up as a host is judged by the address check above, which
        # knows which ones are allowed to be there
        hosts = [h for h in hosts if h not in PROTOCOL_HOSTS
                 and not EXAMPLE_HOST.search(h) and not IS_ADDRESS.fullmatch(h)]
        check(f"{short} names no host but the declared one", hosts, [])

        mails = sorted({m.lower() for m in MAIL.findall(text)
                        if m.lower() != declared_mail.lower()
                        and not EXAMPLE_HOST.search(m.split("@", 1)[1])
                        and not m.lower().startswith("root@")})
        check(f"{short} names no mailbox but the declared one", mails, [])

    group("Everything is in English and says who wrote it")
    for name, blob in sorted(contents.items()):
        text = blob.decode("utf-8", "replace")
        german = sorted(set(m.group(0).lower() for m in re.finditer(GERMAN, text)))
        check(f"{pathlib.Path(name).name} is English", german, [])
        if name.endswith((".php", ".js", ".css")):
            check(f"{pathlib.Path(name).name} carries a copyright notice", COPYRIGHT in text)

    group("Every other file of ours says the same")
    ours = sorted(
        path
        for pattern in ("packaging/*.py", "packaging/watch/*", "packaging/hooks/*",
                        "tests/*.py", "tests/*.php", "tests/*/*.php")
        for path in ROOT.glob(pattern)
        if path.is_file()
    )
    for path in ours:
        if path.name == pathlib.Path(__file__).name:
            # this file holds the word list it searches for, so it matches itself
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        german = sorted(set(m.group(0).lower() for m in re.finditer(GERMAN, text)))
        check(f"{path.relative_to(ROOT)} is English", german, [])
        check(f"{path.relative_to(ROOT)} carries a copyright notice", COPYRIGHT in text)

    package.unlink(missing_ok=True)

    print(f"\n{passed} checks passed", end="")
    if failures:
        print(f", {len(failures)} FAILED:")
        for failure in failures:
            print(f"  {failure}")
        return 1
    print(", none failed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
