#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Checks the rule that decides what a commit message may be, and what a
release note makes of one.

Worth checking because two things depend on it that fail in opposite ways: a
rule too strict refuses a message somebody is trying to write, and a rule too
loose lets a change reach a release with nothing said about it in the note. The
second is the one nobody notices.
"""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "packaging"))
sys.path.insert(0, str(ROOT / "tests"))

import commits  # noqa: E402
import harness  # noqa: E402
from harness import check, group  # noqa: E402


def load(name, path):
    """release-notes.py has a hyphen in it, so it cannot simply be imported."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


notes = load("release_notes", ROOT / "packaging" / "release-notes.py")
linter = load("commit_lint", ROOT / "packaging" / "commit-lint.py")


def refusals(message):
    """@return list[str] what the convention says is wrong with it"""
    return commits.Commit(message).problems()


def main():
    group("A message the convention accepts")
    check("a type and a subject", refusals("fix: something"), [])
    check("a scope as well", refusals("feat(auth): something"), [])
    check("marked as breaking", refusals("fix(auth)!: something"), [])
    check("a scope with a slash in it", refusals("ci(forgejo/build): something"), [])
    check("a body under a blank line", refusals("fix: something\n\nBecause of a reason."), [])
    check("every type this project uses", [t for t in commits.TYPES if refusals(f"{t}: x")], [])

    group("A pull request becomes one release-note commit")
    request = {
        "pull_request": {
            "title": "feat(auth)!: require an admitted identity",
            "body": "Why this is safer.\n\nBREAKING CHANGE: approve existing identities before upgrading.",
        }
    }
    squashed = commits.Commit(linter.pull_request_message(request))
    check("the title is the future commit header", squashed.header, request["pull_request"]["title"])
    check("the description remains its body", squashed.body, request["pull_request"]["body"])
    check("the future commit is accepted", squashed.problems(), [])
    check("its upgrade instruction reaches the note", squashed.breaking_detail,
          "approve existing identities before upgrading.")
    try:
        linter.pull_request_message({"pull_request": {"body": "nothing names this change"}})
        missing_title = False
    except ValueError:
        missing_title = True
    check("an event without a title is refused", missing_title, True)

    group("A message it refuses")
    check("no type at all", len(refusals("Something in plain prose")), 1)
    check("a type nobody agreed on", len(refusals("wibble: something")), 1)
    check("nothing after the colon", len(refusals("fix: ")) >= 1, True)
    check("a full stop at the end", len(refusals("fix: something.")), 1)
    check("an upper-case subject", len(refusals("fix: Something")), 1)
    check("a body glued to the subject", len(refusals("fix: something\nand more")), 1)
    check(
        "a first line longer than a first line should be",
        len(refusals("fix: " + "x" * commits.HEADER_MAX)),
        1,
    )

    group("What git writes itself is left alone")
    check("a merge", refusals("Merge branch 'main' into a-branch"), [])
    check("a revert git wrote", refusals('Revert "fix: something"'), [])
    check("a fixup", refusals("fixup! fix: something"), [])

    group("Reading a message")
    written = commits.Commit("feat(auth)!: allow the root account\n\nWhy it is off by default.\n\n"
                             "BREAKING CHANGE: root is refused unless the setting is on.\n\n"
                             "Co-Authored-By: Somebody <nobody@example.net>")
    check("the type", written.type, "feat")
    check("the scope", written.scope, "auth")
    check("the subject", written.subject, "allow the root account")
    check("it is breaking", written.breaking, True)
    check(
        "the warning stops before the trailer under it",
        written.breaking_detail,
        "root is refused unless the setting is on.",
    )
    check("and it lands at the top of the note", written.heading(), "Breaking")

    footed = commits.Commit("fix: something\n\nBREAKING CHANGE: and it changes behaviour.")
    check("a footer alone is enough to be breaking", footed.breaking, True)
    check("with no bang needed", footed.heading(), "Breaking")

    group("What a release note makes of them")
    written = [
        commits.Commit("feat(api): an endpoint"),
        commits.Commit("fix: a fault"),
        commits.Commit("docs: a page"),
        commits.Commit("chore: tidying"),
        commits.Commit("fix(auth)!: a refusal\n\nBREAKING CHANGE: fill the field in."),
        commits.Commit("Merge branch 'main'"),
    ]
    note = notes.changes(written)

    check("the breaking one comes first", note.startswith("### Breaking"), True)
    check("its warning travels with it", "fill the field in." in note, True)
    check("and it is not repeated under Fixed", note.count("a refusal"), 1)
    check(
        "the sections are in the order the convention lays down",
        [line for line in note.splitlines() if line.startswith("### ")],
        ["### Breaking", "### New", "### Fixed", "### Documentation", "### Housekeeping"],
    )
    check("a scope is shown where there is one", "**api**: an endpoint" in note, True)
    check("and nothing is invented where there is none", "- a fault" in note, True)
    check("what git wrote itself stays out", "Merge branch" not in note, True)

    check("nothing to say says nothing", notes.changes([]), "")

    group("Tags bound the release note")
    with tempfile.TemporaryDirectory() as temporary:
        repository = pathlib.Path(temporary)
        subprocess.run(["git", "init", "-q", str(repository)], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.name", "Release Test"], check=True)
        subprocess.run(
            ["git", "-C", str(repository), "config", "user.email", "nobody@example.net"], check=True
        )

        change = repository / "change"
        change.write_text("first\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "add", "change"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-q", "-m", "feat: first"], check=True)
        subprocess.run(["git", "-C", str(repository), "tag", "-a", "v1.0.0", "-m", "v1.0.0"], check=True)

        change.write_text("second\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repository), "commit", "-qam", "fix: second"], check=True)
        subprocess.run(["git", "-C", str(repository), "tag", "-a", "v1.1.0", "-m", "v1.1.0"], check=True)

        first_span, first_earlier = notes.span_for("v1.0.0", str(repository))
        second_span, second_earlier = notes.span_for("v1.1.0", str(repository))
        check("the first release starts with the history", first_span, "v1.0.0")
        check("the first release names no predecessor", first_earlier, None)
        check("the next release starts after the previous tag", second_span, "v1.0.0..v1.1.0")
        check("the next release names its predecessor", second_earlier, "v1.0.0")

        rendered = subprocess.run(
            [
                sys.executable,
                str(ROOT / "packaging" / "release-notes.py"),
                "--repo",
                str(repository),
                "--tag",
                "v1.1.0",
                "--file",
                "os-openid-connect-1.1.0.pkg",
                "--url",
                "https://example.net/releases/os-openid-connect-1.1.0.pkg",
                "--checksum",
                "0123456789abcdef",
                "--repository",
                "example/project",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        check("the command includes only the new fix", "- second" in rendered and "- first" not in rendered, True)
        check("the command identifies the previous tag", "1 commit(s) since v1.0.0." in rendered, True)
        check("the complete note includes verification and installation", "### Verify and install" in rendered, True)
        check("an unsigned note promises no signature", ".sig" not in rendered, True)
        check("the complete note verifies GitHub build provenance",
              "gh attestation verify" in rendered and "-R example/project" in rendered, True)
        check("verification is restricted to the intended GitHub-hosted release builder",
              "--signer-workflow example/project/.github/workflows/build.yml" in rendered
              and "--deny-self-hosted-runners" in rendered, True)
        check("the note separates workstation verification from firewall installation",
              rendered.index("On an administrator workstation")
              < rendered.index("Copy that verified package")
              < rendered.index("pkg add"), True)
        check("every verification happens before pkg add",
              max(rendered.index("sha256 -c"), rendered.index("gh attestation verify"))
              < rendered.index("pkg add"), True)

        signed = notes.installing(
            "os-openid-connect-1.1.0.pkg",
            "https://example.net/releases/os-openid-connect-1.1.0.pkg",
            "0123456789abcdef",
            True,
            "example/project",
        )
        check("a signed note fetches and verifies the signature", ".sig" in signed and "openssl dgst" in signed, True)
        check("the optional offline signature is also checked before installation",
              signed.index("openssl dgst") < signed.index("pkg add"), True)

    group("A release is attested and published only once")
    workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    checkout_sha = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
    github_upload_sha = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    attest_sha = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    check("both checkout steps use only the pinned Node 24 action",
          workflow.count(checkout_sha) == 2 and workflow.count("actions/checkout@") == 2, True)
    check("the GitHub CI snapshot uploader is pinned", workflow.count(github_upload_sha), 1)
    check("CI snapshots expire and are not built for pull requests or tags",
          workflow.count("retention-days: 14") == 1
          and "github.ref == 'refs/heads/main'" in workflow
          and workflow.count("github.event_name == 'workflow_dispatch'") == 2, True)
    check("the read-only Forgejo mirror does not publish a second snapshot",
          "github.server_url == 'https://github.com'" in workflow
          and "forgejo/upload-artifact@" not in workflow, True)
    check("a CI snapshot carries the package and its checksum",
          "packaging/dist/*.pkg" in workflow and "packaging/dist/*.pkg.sha256" in workflow, True)
    check("the provenance action is pinned", workflow.count(attest_sha), 1)
    check("the attestation receives only its required identity permissions",
          "id-token: write" in workflow and "attestations: write" in workflow, True)
    check("assets enter a draft before its one-way publication",
          workflow.index("gh release create") < workflow.index("gh release upload")
          < workflow.index('gh release edit "$TAG" --draft=false'), True)
    check("a published release is never refreshed",
          "already published and must never be replaced" in workflow
          and "delete-asset" not in workflow and "--clobber" not in workflow, True)
    check("publication verifies GitHub actually made the release immutable",
          "--jq .immutable" in workflow, True)

    group("Every type reaches a section of the note")
    check(
        "none of them fall through to Other",
        [t for t in commits.TYPES if commits.Commit(f"{t}: x").heading() == "Other"],
        [],
    )
    check(
        "and every section a type names is one the note writes",
        sorted({h for h in commits.TYPES.values()} - {name for name, _ in commits.SECTIONS}),
        [],
    )


if __name__ == "__main__":
    harness.run(main)
