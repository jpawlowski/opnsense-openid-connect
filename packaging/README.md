# Building, installing, taking it back

## The version lives in the tag

`build.py` reads it from `git describe`. A tag `v1.2.3` becomes version
`1.2.3`; anything not sitting on a tag carries the distance along
(`1.2.3.4.gabc1234`), so that work in progress never looks like a release.
There is no version number in the source that anyone could forget to bump.

    git tag -a v1.2.3 -m "..." && git push --tags

That is all it takes: GitHub builds the package, writes the release note and
attaches both. `.github/workflows/build.yml` remains valid Forgejo Actions
syntax, but the Forgejo repository is a pull mirror and never publishes a
release of its own.

A tag with a suffix is a pre-release: `v1.0.0-beta1` becomes package version
`1.0.0.beta1` — a hyphen is what `pkg` reads as the end of a package's name, so
it cannot survive into a version — and the release is marked as one.

## The note writes itself

`release-notes.py` reads the commits between the previous tag and this one and
groups them by what each one said it was. Anything marked `!` or carrying a
`BREAKING CHANGE:` footer goes to the top under its own heading, with the
footer's own words — because what an operator needs before upgrading a firewall
is exactly what somebody already wrote down when they made the change, and a
note assembled by hand is a note that gets assembled once.

    python3 packaging/release-notes.py --tag v1.2.3     # see it before tagging

Which is why commit messages have a shape, and why the pipeline refuses one
that does not: see [`../CONTRIBUTING.md`](../CONTRIBUTING.md). `commits.py`
holds the shape, and both the hook and the note read it from there, so what is
enforced and what is read cannot drift apart.

## Building by hand

    python3 packaging/build.py            # version from the tag
    python3 packaging/build.py --check    # check only, write nothing

The result is `packaging/dist/os-openid-connect-<version>.pkg`.

After a successful GitHub `main` or manually requested CI run, the workflow
keeps that commit-versioned package and its checksum as a downloadable **CI
snapshot** for 14 days. It deliberately does not upload packages built from
pull requests, and the read-only Forgejo mirror keeps no duplicate artifact. A
snapshot is never reused as a release asset: release tags rebuild and attest
their own package at the immutable publication boundary.

**It needs neither FreeBSD nor `pkg`.** A FreeBSD package is a compressed tar
archive with `+COMPACT_MANIFEST` and `+MANIFEST` in front and the files under
absolute paths behind them; permissions and ownership ride on the tar entries.
`pkg create` writes zstd, but `pkg add` reads xz just as happily — measured
against pkg 2.3.1. Hence xz: Python does that out of the box, so the build runs
on any machine. Which is exactly why an ordinary Linux CI runner can do it.

## Checking a package before installing it

`pkg` verifies **nothing** about a file handed to it directly: native signatures
are a property of a repository, and this beta does not come from one. Every
published package instead receives a keyless GitHub/Sigstore build-provenance
attestation. It binds the exact package digest to this repository, its workflow
and source commit; GitHub also locks the published tag and release assets.

On an administrator workstation with GitHub CLI:

    gh attestation verify /tmp/<file> \
      -R jpawlowski/opnsense-openid-connect \
      --signer-workflow jpawlowski/opnsense-openid-connect/.github/workflows/build.yml \
      --deny-self-hosted-runners

Only then copy the verified package to the firewall. GitHub CLI and Sigstore
verification are deliberately not installed as runtime dependencies on
OPNsense. Restricting the signer path and runner type prevents an unrelated
workflow or a self-hosted runner in the same repository from satisfying the
documented publisher check.

The checksum remains useful for transfer integrity and can be checked directly
on the firewall before installation:

    fetch -o /tmp/<file>.sha256 <url>.sha256
    sha256 -c $(cut -d' ' -f1 /tmp/<file>.sha256) /tmp/<file>

A checksum next to the file it describes proves only that the download did not
break. Where a separate offline release key is configured, a detached RSA
signature is attached as an additional verification path:

    fetch -o /tmp/<file>.sig <url>.sig
    openssl dgst -sha256 -verify packaging/release-key.pub \
      -signature /tmp/<file>.sig /tmp/<file>

**Setting the key up**, once, on a machine that is not the build host:

    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out release.key
    openssl pkey -in release.key -pubout -out packaging/release-key.pub

The public half belongs in this repository, where anyone can see it change. The
private half goes into the forge's secrets as `PKG_SIGNING_KEY` and nowhere
else. Without that secret the release still has mandatory GitHub build
provenance, release immutability and its checksum.

## Installing

    pkg add os-openid-connect-<version>.pkg

No restart, no service affected — PHP reads the files on the next request.
Anyone signed in notices nothing; the session lives in PHP, not in the module.

**When an upgrade renames files, `pkg delete` first.** `pkg add -f` leaves the
old files in place, and after a rename that means two classes of the same type
and the login button appearing twice. When the paths stay the same, `pkg add -f`
is the better tool: it avoids the seconds-long window in which the button is
missing.

Settings survive either way: they live in `/conf/config.xml` under
`<system><authserver>` and belong to no package.

During the beta there is intentionally no third-party `pkg` repository and no
automatic `pkg install` update path. Native repository fingerprints can be
introduced later without making that infrastructure part of the authentication
plugin's first release boundary.

Release immutability is a one-time GitHub repository setting, not something the
package can switch on. After the attesting workflow has reached the publishing
branch and before creating the next tag, a repository administrator enables and
checks it with:

    gh api --method PUT \
      repos/jpawlowski/opnsense-openid-connect/immutable-releases
    gh api repos/jpawlowski/opnsense-openid-connect/immutable-releases

It intentionally remains off while an older asset-replacing release workflow is
still present on the publishing branch. GitHub applies the setting only to
releases published after it was enabled.

## Taking it back

    pkg delete os-openid-connect

Single sign-on is then gone and signing in works with a username and password.
The entry under *System > Access > Servers* stays but has no effect until a
module is present again.

## Why a package and not a copy

There is no port and no plugin repository for this plugin, so it has to reach
the machine by hand. Copying loose files there would be the worst of the
options: `pkg check` raises an alarm, a firmware update overwrites them without
a word, and nobody can say later where they came from. As a package this holds
instead:

    pkg info os-openid-connect        what is installed
    pkg list os-openid-connect        which files belong to it
    pkg check -s os-openid-connect    do the checksums still match
    pkg which <file>                        where does this file come from
    pkg delete os-openid-connect      cleanly gone again

`automatic=0` in the manifest, so that `pkg autoremove` — which a plugin sync
runs — never treats it as something that came along for the ride.

## Named so the firmware page shows it, registered nowhere

*System > Firmware > Plugins* lists exactly those installed packages whose name
begins with `os-`. That is the whole rule: `FirmwareController` splits the
package name on `-` and keeps it when the first part is `os`. Nothing else is
consulted. So a package called anything else is installed and **invisible**,
and the way somebody forgets that their firewall's login depends on a package
is by never seeing it. Hence `os-openid-connect`.

**What must not come with the name** is a file under
`/usr/local/opnsense/version/`. That is the second half of what core looks at:
`register.php` writes every package it finds there into
`system.firmware.plugins`, and `sync.subr.sh` afterwards runs `pkg install` for
everything registered. This package is in no repository, so that install would
fail — once per plugin sync, for good. Named yes, registered no; the two are
separate mechanisms and only one of them is wanted.

**A side effect worth knowing:** the firmware health page counts packages that
are in none of the configured repositories as orphaned. That is expected, not a
fault — and it is the same page that now shows the package exists at all.

## The watchdog

`/usr/local/sbin/openid-connect-watch`, nightly at 03:01 through
`/usr/local/etc/cron.d/openid-connect.cron`. That is the way the OPNsense
plugins which schedule anything schedule it, and `cron(8)` reads the directory
by itself — no restart, and nothing to switch on. `periodic(8)` would be the
other way and was the way this started, but neither the core package nor any
plugin puts anything under `/usr/local/etc/periodic`, so whether it runs at all
depends on base defaults nobody here maintains.

It checks two things, and the order is deliberate:

1. **Live probe** — the login page is actually fetched and checked for the
   form, the SSO button, a clean closing tag and PHP errors. This is the check
   that matters.
2. **Fingerprint** — a `sha256` over the core files this module hangs
   off. If it differs, the ground has moved.

A mere version change deliberately triggers nothing: OPNsense moves often
without touching those files.

**The anchor lives on the machine, not in the package**
(`/var/db/openid-connect/`). The same package has to run on any OPNsense, and a
fingerprint over core files is only ever true for one of them. The first
`--check` writes it and says so in the log.

    openid-connect-watch --status    show the state, without mail
    openid-connect-watch --check     check; on a finding, mail and syslog
    openid-connect-watch --anchor    re-anchor after reading through
    openid-connect-watch --test      test the mail path

**Where findings go**, and why there is nothing to configure: every finding is
written to the system log, which every OPNsense can do and which is where
somebody goes looking. Findings are *also* mailed to `root` — the address every
daemon on a FreeBSD machine writes to, and the one a mail transport already
knows how to redirect.

A setting of our own would only be a second place to say what
`/etc/mail/aliases` and the mail plugin's own configuration already say, and a
firewall does not need two places for that.

**Mail is best effort, and says so.** OPNsense ships no mail transport at all:
`sendmail` under `/usr/local/sbin` comes from the `os-postfix` plugin, and
without it — or another package providing one — nothing can be delivered. The
watchdog looks for one, and when there is none it writes a line saying the
finding was not mailed rather than failing quietly. `--status` shows which it
is:

    Mail        no transport installed - findings go to the log only

Where a transport exists, mail is sent with an explicit sender (`sendmail -f`)
— without it postfix takes `$myorigin`, and if that is a name which does not
resolve, the far end rejects the mail and nobody finds out.

**What uninstalling leaves behind.** `pkg delete` removes what `pkg` installed:
the watchdog and its cron entry. One thing is written outside that — the anchor
under `/var/db/openid-connect/` — and a post-deinstall script takes it with it,
while leaving it alone during an upgrade.

## When something does go wrong

Signing in locally always remains possible: `authgui.inc` renders the form for
a username and password **before** the SSO block. At worst, over the serial
console or SSH:

    pkg delete -y os-openid-connect
