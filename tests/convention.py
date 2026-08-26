#!/usr/bin/env python3

"""Checks the rule that decides what a commit message may be, and what a
release note makes of one.

Worth checking because two things depend on it that fail in opposite ways: a
rule too strict refuses a message somebody is trying to write, and a rule too
loose lets a change reach a release with nothing said about it in the note. The
second is the one nobody notices.
"""
import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
from unittest import mock

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

    commented = commits.Commit(
        "chore: add a template\n\n<!--\nBREAKING CHANGE: replace this instruction.\n-->\nNone"
    )
    check("a footer example inside an HTML comment is inert", commented.breaking, False)
    check("and contributes no operator instruction", commented.breaking_detail, "")

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

        first = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "v1.0.0^{commit}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        second = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "v1.1.0^{commit}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        with mock.patch.dict(os.environ, {"GITHUB_SHA": first}):
            with mock.patch.object(
                linter,
                "forge_event",
                return_value={"ref": "refs/tags/v1.0.0", "before": "0" * 40},
            ):
                tag_span = linter.pushed_span(str(repository))

        with mock.patch.dict(os.environ, {"GITHUB_SHA": second}):
            with mock.patch.object(
                linter,
                "forge_event",
                return_value={"ref": "refs/heads/main", "before": first},
            ):
                branch_span = linter.pushed_span(str(repository))

        check("the first tag introduces no commit messages", tag_span, f"{first}..{first}")
        check("and therefore re-lints none of the history", commits.read(tag_span, str(repository)), [])
        check("a branch push still checks what it introduced", branch_span, f"{first}..{second}")
        check("and that range contains the new commit", len(commits.read(branch_span, str(repository))), 1)

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

        stable_after_legacy_beta = subprocess.run(
            [
                sys.executable,
                str(ROOT / "packaging" / "release-notes.py"),
                "--repo",
                str(repository),
                "--tag",
                "v1.0.0",
                "--file",
                "os-openid-connect-1.0.0.pkg",
                "--url",
                "https://example.net/releases/os-openid-connect-1.0.0.pkg",
                "--checksum",
                "0123456789abcdef",
                "--repository",
                "example/project",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        check("the first stable note removes a legacy beta before installing",
              "pkg delete os-openid-connect" in stable_after_legacy_beta
              and "pkg add /tmp/os-openid-connect-1.0.0.pkg" in stable_after_legacy_beta
              and stable_after_legacy_beta.index("pkg delete") < stable_after_legacy_beta.index("pkg add")
              and "v1.0.0-betaN" in stable_after_legacy_beta, True)
        check("the legacy beta migration never leaves retired files behind",
              "pkg add -f" not in stable_after_legacy_beta, True)
        check("later stable notes retain the ordinary install command",
              "pkg add -f" not in rendered and "pkg add /tmp/os-openid-connect-1.1.0.pkg" in rendered,
              True)

    group("A release is attested and published only once")
    workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
    checkout_sha = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
    github_upload_sha = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    attest_sha = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"
    check("both checkout steps use only the pinned Node 24 action",
          workflow.count(checkout_sha) == 2 and workflow.count("actions/checkout@") == 2, True)
    check("the GitHub CI snapshot uploader is pinned", workflow.count(github_upload_sha), 1)
    check("CI snapshots cover pull requests but not tags, with shorter PR retention",
          "retention-days: ${{ github.event_name == 'pull_request' && 3 || 14 }}" in workflow
          and "untrusted-pr-{0}-{1}" in workflow
          and workflow.count("github.event_name == 'pull_request' ||") == 2
          and "github.ref == 'refs/heads/main'" in workflow
          and workflow.count("github.event_name == 'workflow_dispatch'") == 2
          and workflow.count("!startsWith(github.ref, 'refs/tags/')") == 2, True)
    check("the read-only Forgejo mirror does not publish a second snapshot",
          "github.server_url == 'https://github.com'" in workflow
          and "forgejo/upload-artifact@" not in workflow, True)
    check("a CI snapshot carries the package, its checksum and a trust notice",
          "packaging/dist/*.pkg" in workflow
          and "packaging/dist/*.pkg.sha256" in workflow
          and "packaging/dist/CI-SNAPSHOT.txt" in workflow
          and "UNTRUSTED PULL REQUEST SNAPSHOT" in workflow, True)
    check("the provenance action is pinned", workflow.count(attest_sha), 1)
    check("only a GitHub tag push can enter the publication job",
          "github.event_name == 'push'" in workflow
          and "startsWith(github.ref, 'refs/tags/v')" in workflow
          and "github.server_url == 'https://github.com'" in workflow, True)
    check("the attestation receives only its required identity permissions",
          "id-token: write" in workflow and "attestations: write" in workflow, True)
    check("the provenance statement covers the exact package built by this job",
          "subject-path: ${{ steps.build.outputs.path }}" in workflow, True)
    check("the release job requires no repository-administration API access",
          "immutable-releases" not in workflow, True)
    check("provenance is created before any release is published",
          workflow.index("Attest package build provenance")
          < workflow.index("Publish the complete immutable GitHub release"), True)
    check("assets enter a draft before its one-way publication",
          workflow.index("gh release create") < workflow.index("gh release upload")
          < workflow.index('gh release edit "$TAG" --draft=false'), True)
    check("the draft is bound to the already existing tag",
          'gh release create "$TAG" --verify-tag --draft' in workflow, True)
    check("publication inventories the complete asset set before becoming immutable",
          "Draft release is missing expected asset" in workflow
          and "Draft release contains an unexpected asset" in workflow, True)
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
