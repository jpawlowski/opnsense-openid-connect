#!/usr/bin/env python3

"""Builds the finished package - without `pkg`, using only the standard library.

A FreeBSD package is a compressed tar archive with three kinds of entry, in
this order:

    +COMPACT_MANIFEST   the metadata without the file list
    +MANIFEST           the same metadata plus files: path -> "1$<sha256>"
    /usr/local/...      the files themselves, under an ABSOLUTE path

Permissions and ownership are not in the manifest but on the tar entries; `pkg`
takes them from there.

`pkg create` writes zstd, but `pkg add` reads xz just as happily - measured
against pkg 2.3.1. Hence xz: Python does that out of the box, so this build
runs on any machine rather than only on a FreeBSD one.

    python3 packaging/build.py                    # version from the git tag
    python3 packaging/build.py --version 1.2.3    # version by hand
    python3 packaging/build.py --check            # check only, write nothing

The result is packaging/dist/<name>-<version>.pkg.
"""
import argparse
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tarfile

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
SRC = REPO / "src" / "opnsense"
DIST = HERE / "dist"

# The os- prefix is not decoration: System > Firmware > Plugins lists exactly
# those installed packages whose name begins with it, by name and nothing else.
# Without it this package is installed and invisible, which is how somebody
# forgets that their firewall's login depends on it.
#
# What must NOT come with it is a file under /usr/local/opnsense/version/.
# That is the other half of what core looks at: register.php writes any package
# it finds there into system.firmware.plugins, and every plugin sync afterwards
# runs `pkg install` for what is registered. This package is in no repository,
# so that install would fail, once per sync, for good. Named yes, registered no.
NAME = "os-openid-connect"
ORIGIN = "security/openid-connect"
PREFIX = "/usr/local"
TARGET = "usr/local/opnsense"
SOURCE_URL = "https://github.com/jpawlowski/opnsense-openid-connect"

# Outside the source tree: the watchdog and the nightly run that starts it.
EXTRA = [
    ("watch/openid-connect-watch", "usr/local/sbin/openid-connect-watch", 0o755),
    ("watch/openid-connect-refresh", "usr/local/sbin/openid-connect-refresh", 0o755),
    ("watch/openid-connect.cron", "usr/local/etc/cron.d/openid-connect.cron", 0o644),
]
LICENSE_IDS = ("BSD2CLAUSE", "APACHE20")
LICENSE_NAMES = {
    "BSD2CLAUSE": 'BSD 2-clause "Simplified" License',
    "APACHE20": "Apache License 2.0",
}
LICENSE_GROUPS = {
    "BSD2CLAUSE": "FSF OSI COPYFREE",
    "APACHE20": "FSF OSI",
}
LICENSE_PERMISSIONS = "dist-mirror dist-sell pkg-mirror pkg-sell auto-accept"

# The watchdog writes an anchor on the machine it runs on, under /var/db. pkg
# removes what it installed and nothing else, so without this the fingerprint of
# a package that is gone would stay behind for good.
#
# PKG_UPGRADE is a best-effort guard: where pkg sets it, an upgrade keeps the
# anchor and a real removal drops it. Where it does not, the anchor is written
# again on the next run and the only cost is one line in the log.
POST_INSTALL = """\
rm -f /var/lib/php/tmp/opnsense_acl_cache.json /tmp/opnsense_acl_cache.json
/usr/local/sbin/pluginctl -s cron restart
"""

POST_DEINSTALL = """\
rm -f /var/lib/php/tmp/opnsense_acl_cache.json /tmp/opnsense_acl_cache.json
[ "${PKG_UPGRADE:-false}" = "true" ] && exit 0
rm -f /var/db/openid-connect/core.digest /var/db/openid-connect/core.version
rm -rf /var/db/openid-connect/cache /var/db/openid-connect/runtime /var/db/openid-connect/dpop
rm -f /var/lib/php/sessions/.openidconnect-sessions
rm -f /var/lib/php/sessions/.openidconnect-logout-tokens
rm -f /var/lib/php/sessions/.openidconnect-security-events
rm -f /var/lib/php/sessions/.openidconnect-transactions
rm -f /var/lib/php/sessions/.openidconnect-lifecycle-tests
rm -f /var/lib/php/sessions/.openidconnect-pending-identities
rmdir /var/db/openid-connect 2>/dev/null
/usr/local/sbin/pluginctl -s cron restart
"""

COMMENT = "OpenID Connect sign-in for the OPNsense web interface"

DESC = """\
Sign in to the OPNsense web interface through OpenID Connect.

Adds a "Login with ..." entry to the login page and turns a successful
exchange into a web interface session. Signing in locally with a username
and password is untouched and always remains available.

Privileges stay local unless asked otherwise: no group claim is consumed
until a group claim is configured, so taking over the identity provider
does not by itself grant anyone rights on the firewall.

Checked on every exchange: the signature algorithm, the expiry, the nonce,
that every used UserInfo response is bound to the issued token, and that
the login began under an accepted address. PKCE is required and the session
id is rotated once the session gains privileges. Everything an
installation differs on is a setting under System > Access > Servers.

Contains only additional files below /usr/local/opnsense/mvc/ plus the
watchdog /usr/local/sbin/openid-connect-watch, its daily run and the package
licences. No file of the core package is replaced or altered.

BSD-2-Clause, with Apache-2.0 portions in bundled provider icons. Runtime
cryptography is provided by the phpseclib package that is part of OPNsense;
this package does not bundle an OpenID Connect library.
"""


def git(*args, default=None):
    try:
        out = subprocess.run(["git", "-C", str(REPO), *args],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return default


def pkg_version(described):
    """What `pkg` can carry, out of what git says.

    A hyphen is what pkg reads as the boundary between a package's name and its
    version, so `1.0.0-beta1` would make `pkg query %n-%v` and everything built
    on it - the watchdog included - answer nonsense. Every character that is not
    a digit, a letter or a dot becomes a dot:

        v1.0.0-beta1        -> 1.0.0.beta1
        v1.0.0-3-gabc1234   -> 1.0.0.3.gabc1234

    Note that pkg reads a longer version as the newer one, so 1.0.0.beta1 sorts
    *after* 1.0.0 rather than before it. Nothing here depends on that ordering -
    there is no repository to upgrade from, only `pkg add` by hand - but a
    pre-release is a tag, not a package that overtakes its own release.
    """
    return re.sub(r"[^0-9A-Za-z.]", ".", described.lstrip("v"))


def version_from_git():
    """The version comes from the tag - exactly one place where it is stated.

    A tag v1.2.3 becomes 1.2.3. When HEAD is not on a tag, what `git describe`
    adds comes along, so that work in progress never looks like a release.
    """
    exact = git("describe", "--tags", "--exact-match")
    if exact:
        return pkg_version(exact)

    described = git("describe", "--tags", "--always", "--dirty")
    if not described:
        return "0.0.0.unversioned"

    return pkg_version(described)


def license_entries(version):
    """The licence directory FreeBSD's ports framework would install for this package."""
    directory = f"usr/local/share/licenses/{NAME}-{version}"
    distribution = f"{NAME}-{version}"
    report = "This package has multiple licenses (all of):\n" + "".join(
        f"- {license_id} ({LICENSE_NAMES[license_id]})\n" for license_id in LICENSE_IDS
    )
    catalog = [
        f"_LICENSE={' '.join(LICENSE_IDS)}",
        "_LICENSE_COMB=multi",
        f"_LICENSE_NAME=Multiple (all of): {' '.join(LICENSE_IDS)}",
        f"_LICENSE_PERMS={LICENSE_PERMISSIONS}",
        "_LICENSE_GROUPS=FSF OSI",
    ]
    for license_id in LICENSE_IDS:
        catalog.extend([
            f"_LICENSE_NAME_{license_id} ={LICENSE_NAMES[license_id]}",
            f"_LICENSE_PERMS_{license_id} ={LICENSE_PERMISSIONS}",
            f"_LICENSE_GROUPS_{license_id} ={LICENSE_GROUPS[license_id]}",
            f"_LICENSE_DISTFILES_{license_id} ={distribution}",
        ])
    apache = (
        SRC / "mvc/app/library/OPNsense/OpenIDConnect/assets/provider-icons/LICENSE.apache-2.0"
    ).read_bytes()
    return [
        (f"/{directory}/catalog.mk", ("\n".join(catalog) + "\n").encode(), 0o644),
        (f"/{directory}/LICENSE", report.encode(), 0o644),
        (f"/{directory}/BSD2CLAUSE", (REPO / "LICENSE").read_bytes(), 0o644),
        (f"/{directory}/APACHE20", apache, 0o644),
    ]


def collect(version):
    """@return list[(archive path, contents, mode)] in a stable order"""
    entries = []
    for path in sorted(SRC.rglob("*")):
        if path.is_file():
            archive = "/" + TARGET + "/" + str(path.relative_to(SRC))
            entries.append((archive, path.read_bytes(), 0o644))

    for source, target, mode in EXTRA:
        entries.append(("/" + target, (HERE / source).read_bytes(), mode))

    # A standalone package does not have the repository root around it. Match the
    # versioned multi-licence layout installed by FreeBSD's ports framework.
    entries.extend(license_entries(version))

    return entries


def manifest_for(version, entries):
    flatsize = sum(len(blob) for _, blob, _ in entries)
    built_from = git("rev-parse", "HEAD", default="unknown")
    if git("status", "--porcelain", default=""):
        built_from += ".dirty"
    compact = {
        "name": NAME,
        "origin": ORIGIN,
        "version": version,
        "comment": COMMENT,
        "maintainer": "ops@pwlski.de",
        "www": SOURCE_URL,
        "abi": "*",
        "arch": "*",
        "prefix": PREFIX,
        "flatsize": flatsize,
        "desc": DESC,
        "categories": ["security"],
        # Use the native FreeBSD/OPNsense identifier so `pkg info` exposes the
        # license as structured package metadata. Keep SPDX in annotations for
        # tools and readers outside the FreeBSD ports vocabulary.
        "licenselogic": "multi",
        "licenses": ["BSD2CLAUSE", "APACHE20"],
        # explicitly installed, so `pkg autoremove` - which a plugin sync runs -
        # never considers it something that came along for the ride
        "automatic": False,
        "scripts": {"post-install": POST_INSTALL, "post-deinstall": POST_DEINSTALL},
        "annotations": {
            "license": "BSD-2-Clause AND Apache-2.0",
            "runtime_crypto": "OPNsense phpseclib3",
            "source": SOURCE_URL,
            "built_from": built_from,
        },
    }
    full = dict(compact)
    full["files"] = {
        path: "1$" + hashlib.sha256(blob).hexdigest() for path, blob, _ in entries
    }

    return compact, full


def write(target, compact, full, entries):
    DIST.mkdir(parents=True, exist_ok=True)
    with tarfile.open(target, "w:xz", format=tarfile.USTAR_FORMAT) as tar:
        members = [
            ("+COMPACT_MANIFEST", json.dumps(compact).encode(), 0o644),
            ("+MANIFEST", json.dumps(full).encode(), 0o644),
            *entries,
        ]
        for name, blob, mode in members:
            info = tarfile.TarInfo(name)
            info.size = len(blob)
            info.mode = mode
            info.mtime = 0  # same input, same package
            info.uid = info.gid = 0
            info.uname, info.gname = "root", "wheel"
            tar.addfile(info, io.BytesIO(blob))


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", help="version; otherwise from the git tag")
    parser.add_argument("--check", action="store_true", help="check only, write nothing")
    args = parser.parse_args()

    if not SRC.is_dir():
        sys.exit(f"STOP: {SRC} is missing")

    version = args.version or version_from_git()
    entries = collect(version)
    compact, full = manifest_for(version, entries)

    print(f"{NAME}-{version}")
    print(f"  {len(entries)} files, {compact['flatsize'] / 1024:.0f} kB unpacked")
    print(f"  crypto:     {compact['annotations']['runtime_crypto']}")
    print(f"  built from: {compact['annotations']['built_from'][:12]}")

    if args.check:
        print("  (checked only, nothing written)")
        return 0

    target = DIST / f"{NAME}-{version}.pkg"
    write(target, compact, full, entries)
    print(f"  {target} ({target.stat().st_size / 1024:.0f} kB)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
