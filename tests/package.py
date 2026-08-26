#!/usr/bin/env python3

"""Checks the package that build.py produces, and the hygiene of what goes into it.

Two kinds of check live here:

  * the shape of the archive - `pkg` will not tell us it is wrong until someone tries to
    install it, and by then it is on a firewall
  * what the files may and may not contain - OPNsense-style licence blocks only in
    installed application code, no German, private addresses, hosts or mailboxes

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
import xml.etree.ElementTree as ET

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
    # Required license address in the bundled verbatim Apache-2.0 terms.
    "www.apache.org",
    # XML namespace carried by the package-owned SVG provider marks.
    "www.w3.org",
    # Commit-pinned OPNsense artwork used by generated provider applications.
    "raw.githubusercontent.com",
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


def project_notice():
    """Return the OPNsense-style spelling of the holder named by the project licence."""
    for line in (ROOT / "LICENSE").read_text().splitlines():
        if line.startswith("Copyright"):
            holder = line.split(",", 1)[1].strip() if "," in line else line
            year = re.search(r"\b(\d{4})\b", line)
            return f"Copyright (C) {year.group(1)} {holder}" if year else None

    return None


COPYRIGHT = project_notice()
OPNSENSE_LICENSE_MARKERS = (
    "Redistribution and use in source and binary forms, with or without",
    "1. Redistributions of source code must retain the above copyright notice,",
    "2. Redistributions in binary form must reproduce the above copyright",
    "THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,",
    "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE",
)


def carries_opnsense_header(text):
    return COPYRIGHT in text and all(marker in text for marker in OPNSENSE_LICENSE_MARKERS)


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
    if COPYRIGHT is None:
        sys.exit("LICENSE carries no copyright holder for the application headers")

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
    check("it names all applicable licences", manifest["annotations"].get("license"),
          "BSD-2-Clause AND Apache-2.0")
    check("pkg sees licences for distinct package portions", manifest.get("licenselogic"), "multi")
    check("pkg sees the native BSD and Apache identifiers", manifest.get("licenses"),
          ["BSD2CLAUSE", "APACHE20"])
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
    refresh = contents.get("/usr/local/sbin/openid-connect-refresh", b"").decode()
    check("background PAR recovery accepts every supported client credential",
          "hasClientAuthenticationCredential()" in refresh
          and "$settings->clientSecret() === ''" not in refresh)
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
    cron_restart = "/usr/local/sbin/pluginctl -s cron restart"
    check("installing activates the bundled cron jobs",
          install.rstrip().endswith(cron_restart))
    check("uninstalling drops the bundled cron jobs from the running daemon",
          deinstall.rstrip().endswith(cron_restart))
    check("uninstalling takes the watchdog's anchor with it",
          "/var/db/openid-connect" in deinstall)
    check("uninstalling takes provider cache and circuit state with it",
          "/var/db/openid-connect/cache /var/db/openid-connect/runtime" in deinstall)
    check("uninstalling takes DPoP private keys and nonces with it",
          "/var/db/openid-connect/dpop" in deinstall)
    check("uninstalling takes the OIDC session index with it",
          "/var/lib/php/sessions/.openidconnect-sessions" in deinstall)
    check("uninstalling takes the logout replay index with it",
          "/var/lib/php/sessions/.openidconnect-logout-tokens" in deinstall)
    check("uninstalling takes the Shared Signals replay index with it",
          "/var/lib/php/sessions/.openidconnect-security-events" in deinstall)
    check("uninstalling takes the form-post transaction index with it",
          "/var/lib/php/sessions/.openidconnect-transactions" in deinstall)
    check("uninstalling takes the lifecycle test index with it",
          "/var/lib/php/sessions/.openidconnect-lifecycle-tests" in deinstall)
    check("uninstalling takes pending identity hints with it",
          "/var/lib/php/sessions/.openidconnect-pending-identities" in deinstall)
    check("but an upgrade keeps it", "PKG_UPGRADE" in deinstall)

    group("What ships with it")
    check("no Jumbojett library or licence is included",
          [n for n in contents if n.endswith(("OpenIDConnectClient.php", "LICENSE.jumbojett"))], [])
    check("no documentation is installed onto the firewall",
          [n for n in contents if n.endswith(".md")], [])
    license_directory = f"/usr/local/share/licenses/os-openid-connect-{VERSION}"
    packaged_licenses = {
        pathlib.PurePosixPath(name).name
        for name in contents
        if name.startswith(license_directory + "/")
    }
    check("the package carries FreeBSD's multi-licence directory shape",
          packaged_licenses, {"LICENSE", "catalog.mk", "BSD2CLAUSE", "APACHE20"})
    check("the packaged BSD terms are the central project licence",
          contents.get(license_directory + "/BSD2CLAUSE"), (ROOT / "LICENSE").read_bytes())
    check("the package reports that both licences apply",
          contents.get(license_directory + "/LICENSE", b"").decode("utf-8", "replace"),
          'This package has multiple licenses (all of):\n'
          '- BSD2CLAUSE (BSD 2-clause "Simplified" License)\n'
          '- APACHE20 (Apache License 2.0)\n')
    license_catalog = contents.get(license_directory + "/catalog.mk", b"").decode("utf-8", "replace")
    check("the package catalogue is the FreeBSD native multi-licence catalogue",
          license_catalog,
          "_LICENSE=BSD2CLAUSE APACHE20\n"
          "_LICENSE_COMB=multi\n"
          "_LICENSE_NAME=Multiple (all of): BSD2CLAUSE APACHE20\n"
          "_LICENSE_PERMS=dist-mirror dist-sell pkg-mirror pkg-sell auto-accept\n"
          "_LICENSE_GROUPS=FSF OSI\n"
          '_LICENSE_NAME_BSD2CLAUSE =BSD 2-clause "Simplified" License\n'
          "_LICENSE_PERMS_BSD2CLAUSE =dist-mirror dist-sell pkg-mirror pkg-sell auto-accept\n"
          "_LICENSE_GROUPS_BSD2CLAUSE =FSF OSI COPYFREE\n"
          f"_LICENSE_DISTFILES_BSD2CLAUSE =os-openid-connect-{VERSION}\n"
          "_LICENSE_NAME_APACHE20 =Apache License 2.0\n"
          "_LICENSE_PERMS_APACHE20 =dist-mirror dist-sell pkg-mirror pkg-sell auto-accept\n"
          "_LICENSE_GROUPS_APACHE20 =FSF OSI\n"
          f"_LICENSE_DISTFILES_APACHE20 =os-openid-connect-{VERSION}\n")
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
    check("no generated-application icon is packaged", [
        name for name in contents if "/OPNsense/OpenIDConnect/assets/application-icons/" in name
    ], [])
    apache_license_path = (
        "/usr/local/opnsense/mvc/app/library/OPNsense/OpenIDConnect/"
        "assets/provider-icons/LICENSE.apache-2.0"
    )
    apache_notice_path = (
        "/usr/local/opnsense/mvc/app/library/OPNsense/OpenIDConnect/"
        "assets/provider-icons/NOTICE.apache-2.0"
    )
    apache_license = contents.get(apache_license_path, b"").decode("utf-8", "replace")
    apache_notice = contents.get(apache_notice_path, b"").decode("utf-8", "replace")
    check("the package gives icon recipients the Apache 2.0 licence",
          "Apache License\n                           Version 2.0" in apache_license, True)
    check("the FreeBSD licence directory carries the same Apache terms",
          contents.get(license_directory + "/APACHE20", b"").decode("utf-8", "replace"),
          apache_license)
    check("the package preserves Dashboard Icons attribution",
          "Copyright (c) 2024 Bjorn Lammers, Meier Lukas, Thomas Camlong and Homarr Labs"
          in apache_notice, True)
    apache_derived_icons = {
        "apple.svg", "authelia.svg", "dex.svg", "fusionauth.svg", "gitlab.svg",
        "google.svg", "keycloak.svg", "linkedin.svg", "okta.svg", "oracle_idcs.svg",
        "pocketid.svg", "slack.svg", "yahoo.svg", "zitadel.svg",
    }
    missing_apache_notices = sorted(
        name for name in apache_derived_icons
        if "Apache-2.0" not in contents[
            next(path for path in contents if path.endswith("/provider-icons/" + name))
        ].decode("utf-8", "replace")
    )
    check("every modified Apache icon identifies its source licence",
          missing_apache_notices, [])
    branded_icons = {
        name: contents[name].decode("utf-8", "replace")
        for name in contents
        if "/OPNsense/OpenIDConnect/assets/provider-icons/" in name
        and name.endswith(".svg") and not name.endswith("/general.svg")
    }
    check("named provider profiles use vector brand artwork rather than letter tiles",
          [pathlib.PurePosixPath(name).name for name, svg in branded_icons.items()
           if "<path" not in svg or "<text" in svg], [])
    authentik_icons = [svg for name, svg in branded_icons.items() if name.endswith("/authentik.svg")]
    check("authentik uses its orange official mark", len(authentik_icons) == 1
          and "#fd4b2d" in authentik_icons[0].lower(), True)
    all_provider_icons = {
        name: contents[name].decode("utf-8", "replace")
        for name in contents
        if "/OPNsense/OpenIDConnect/assets/provider-icons/" in name and name.endswith(".svg")
    }
    malformed_icon_geometry = []
    visible_white_layers = []
    for name, svg in sorted(all_provider_icons.items()):
        try:
            root = ET.fromstring(svg)
            viewbox = [float(part) for part in re.split(r"[\s,]+", root.attrib.get("viewBox", "").strip())]
        except (ET.ParseError, ValueError):
            malformed_icon_geometry.append(pathlib.PurePosixPath(name).name)
            continue
        if (len(viewbox) != 4 or viewbox[2] <= 0 or viewbox[3] <= 0
                or abs(viewbox[2] - viewbox[3]) > 0.001
                or "width" in root.attrib or "height" in root.attrib):
            malformed_icon_geometry.append(pathlib.PurePosixPath(name).name)

        def find_visible_white(element, inside_mask=False):
            tag = element.tag.rsplit("}", 1)[-1]
            inside_mask = inside_mask or tag == "mask"
            paint = " ".join([
                element.attrib.get("fill", ""),
                element.attrib.get("stroke", ""),
                element.attrib.get("style", ""),
            ])
            if not inside_mask and re.search(
                r"(?:^|[\s:;])(?:#fff(?:fff)?|white)(?:$|[\s;])", paint, re.I
            ):
                visible_white_layers.append(pathlib.PurePosixPath(name).name)
            for child in element:
                find_visible_white(child, inside_mask)

        find_visible_white(root)
    check("provider icon artboards share one square CSS geometry", malformed_icon_geometry, [])
    check("light icon details are transparent mask cut-outs, not visible white layers",
          sorted(set(visible_white_layers)), [])
    generic_icons = [svg for name, svg in all_provider_icons.items() if name.endswith("/general.svg")]
    check("Generic uses the official orange OpenID glyph", len(generic_icons) == 1
          and "#f78c40" in generic_icons[0].lower() and "<text" not in generic_icons[0], True)
    microsoft_icons = [svg for name, svg in all_provider_icons.items() if name.endswith("/entra.svg")]
    check("Microsoft uses the official four-colour sign-in symbol", len(microsoft_icons) == 1
          and all(colour in microsoft_icons[0].lower()
                  for colour in ("#f25022", "#7fba00", "#00a4ef", "#ffb900")), True)
    keycloak_icons = [svg for name, svg in all_provider_icons.items() if name.endswith("/keycloak.svg")]
    check("Keycloak keeps an open centre in single-colour rendering", len(keycloak_icons) == 1
          and "#4d4d4d" not in keycloak_icons[0].lower()
          and all(colour in keycloak_icons[0].lower()
                  for colour in ("#00b8e3", "#33c6e9", "#008aaa")), True)
    button_styles = [contents[name].decode("utf-8", "replace") for name in contents
                     if name.endswith("/OPNsense/OpenIDConnect/assets/login-button.css")]
    check("every login button reserves the same 24-pixel icon column", len(button_styles) == 1
          and re.search(
              r"\.login-sso-mark\s*\{[^}]*width:\s*24px;[^}]*height:\s*24px;"
              r"[^}]*flex:\s*0\s+0\s+24px;",
              button_styles[0], re.S
          ) is not None, True)
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

    group("Everything is in English and application code follows OPNsense")
    for name, blob in sorted(contents.items()):
        text = blob.decode("utf-8", "replace")
        german = sorted(set(m.group(0).lower() for m in re.finditer(GERMAN, text)))
        check(f"{pathlib.Path(name).name} is English", german, [])
        if name.endswith((".php", ".js", ".css")) or name == "/usr/local/sbin/openid-connect-refresh":
            check(f"{pathlib.Path(name).name} carries the complete OPNsense licence block",
                  carries_opnsense_header(text), True)

    group("Every other file of ours is English")
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

    group("First-party notices follow file roles")
    tracked = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True
    ).stdout.decode().split("\0")
    tracked = [ROOT / name for name in tracked if name and (ROOT / name).is_file()]
    expected_notices = {ROOT / "LICENSE", ROOT / "packaging/watch/openid-connect-refresh"}
    expected_notices.update(
        path for path in tracked
        if path.is_relative_to(ROOT / "src/opnsense") and path.suffix in {".php", ".js", ".css"}
    )
    actual_notices = {ROOT / "LICENSE"}
    actual_notices.update({
        path for path in tracked
        if COPYRIGHT in path.read_text(encoding="utf-8", errors="replace")
    })
    check("only installed application code and the central licence name the holder",
          sorted(str(path.relative_to(ROOT)) for path in actual_notices),
          sorted(str(path.relative_to(ROOT)) for path in expected_notices))

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
