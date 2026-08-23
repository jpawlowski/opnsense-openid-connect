#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Writes the note that goes on a release, out of the commits it contains.

    python3 packaging/release-notes.py --tag v1.2.3
    python3 packaging/release-notes.py --tag v1.2.3 \\
        --file os-openid-connect-1.2.3.pkg \\
        --url https://.../releases/download/v1.2.3/... \\
        --checksum <sha256> --repository owner/repository --signed --built-from <sha>

Read from the commits rather than written by hand, because a note written by
hand is a note that is written once and then not again - and because what an
installation has to know before it upgrades is exactly what somebody already
wrote down when they made the change. `type(scope)!:` and BREAKING CHANGE put
that first; see commits.py for the shape and commit-lint.py for what holds
messages to it.

Without --file it prints the changes alone, which is what a person wants when
they are about to tag something and would like to see what they are tagging.
"""
import argparse
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import commits  # noqa: E402  (it sits next door, and next door has to be on the path first)


def git(*args, repo=".", default=None):
    try:
        return subprocess.run(
            ["git", "-C", repo, *args], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return default


def span_for(tag, repo="."):
    """The range a tag covers: from the tag before it, or from the beginning.

    @return tuple[str, str|None] the range, and the earlier tag when there is one
    """
    earlier = git("describe", "--tags", "--abbrev=0", f"{tag}^", repo=repo)

    return (f"{earlier}..{tag}" if earlier else tag), earlier


def entry(commit, commit_url=""):
    """One line of the note."""
    said = commit.subject
    if commit.scope:
        said = f"**{commit.scope}**: {said}"

    short = commit.sha[:12]
    where = f" ([{short}]({commit_url}{commit.sha}))" if commit_url and short else ""

    line = f"- {said}{where}"
    if commit.breaking and commit.breaking_detail:
        detail = " ".join(commit.breaking_detail.split())
        line += f"\n  <br>{detail}"

    return line


def changes(entries, commit_url=""):
    """The sections of the note, in the order commits.SECTIONS gives them."""
    by_heading = {}
    for commit in entries:
        if commit.generated:
            continue
        by_heading.setdefault(commit.heading(), []).append(commit)

    written = []
    for heading, _ in commits.SECTIONS:
        found = by_heading.pop(heading, [])
        if not found:
            continue
        if heading == "Breaking":
            written.append("### Breaking\n\n"
                           "Read these before upgrading: each one can turn a login that "
                           "worked into one that does not.\n")
        else:
            written.append(f"### {heading}\n")
        written.append("\n".join(entry(commit, commit_url) for commit in found))
        written.append("")

    return "\n".join(written).strip("\n")


def installing(file, url, checksum, signed, repository=""):
    """The half of the note that is the same every time, and has to be right."""
    workstation = [
        "On an administrator workstation:",
        "",
        f"    curl --fail --location --output /tmp/{file} \\",
        f"      {url}",
    ]
    if repository:
        workstation += [
            f"    gh attestation verify /tmp/{file} \\",
            f"      -R {repository} \\",
            f"      --signer-workflow {repository}/.github/workflows/build.yml \\",
            "      --deny-self-hosted-runners",
        ]
    if signed:
        workstation += [
            "",
            "Optionally verify the additional offline signature against",
            "`packaging/release-key.pub` from the reviewed source tree:",
            "",
            f"    curl --fail --location --output /tmp/{file}.sig {url}.sig",
            "    openssl dgst -sha256 -verify release-key.pub \\",
            f"      -signature /tmp/{file}.sig /tmp/{file}",
        ]

    return "\n".join([
        "### Verify and install",
        "",
        "`pkg` checks nothing about a file handed to it directly. Establish its",
        "GitHub/Sigstore provenance before the package reaches the firewall.",
        "",
        *workstation,
        "",
        "Copy that verified package to `/tmp` on the firewall. Confirm that the",
        "transfer preserved its exact bytes, then install it:",
        "",
        f"    sha256 -c {checksum} /tmp/{file}",
        "",
        f"    pkg add /tmp/{file}",
        "",
        "No restart, no service affected. Signing in locally with a username and",
        "password is untouched; the way back is always",
        "`pkg delete os-openid-connect`.",
    ])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True, help="the tag being released")
    parser.add_argument("--repo", default=".", help="where the repository is")
    parser.add_argument("--file", help="name of the package attached to the release")
    parser.add_argument("--url", default="", help="where that package can be fetched")
    parser.add_argument("--checksum", default="", help="its sha256")
    parser.add_argument("--repository", default="", help="GitHub owner/repository for provenance verification")
    parser.add_argument("--signed", action="store_true", help="a signature is attached as well")
    parser.add_argument("--commit-url", default="", help="prefix a commit id is a link under")
    parser.add_argument("--built-from", default="", help="the commit it was built from")
    args = parser.parse_args()

    span, earlier = span_for(args.tag, args.repo)
    try:
        entries = commits.read(span, args.repo)
    except subprocess.CalledProcessError as problem:
        sys.exit(f"cannot read {span}: {problem.stderr.strip()}")

    said = changes(entries, args.commit_url)
    if not said:
        said = "Nothing but merges since the last release."

    note = [said, ""]
    if args.file:
        note += [installing(args.file, args.url, args.checksum, args.signed, args.repository), ""]
    note.append(
        f"{len(entries)} commit(s) since {earlier}." if earlier
        else f"{len(entries)} commit(s), the first release."
    )
    if args.built_from:
        note.append(f"Built from `{args.built_from}`.")

    print("\n".join(note).strip("\n"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
