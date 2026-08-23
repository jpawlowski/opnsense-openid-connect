#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Prepare an agent's clone and run the deterministic test tier when needed."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse


REPOSITORY = Path(__file__).resolve().parents[2]
RELEVANT_PATHS = (
    ".agents",
    ".claude",
    ".codex",
    ".forgejo/workflows",
    ".github/hooks",
    ".github/scripts",
    ".github/workflows",
    "LICENSE",
    "packaging",
    "src",
    "tests",
)
START_FETCH_TTL = 5 * 60
ACTIVE_FETCH_TTL = 10 * 60
FETCH_TIMEOUT = 20
# A fork can fetch the canonical and publishing remotes sequentially while
# holding the shared lock. Another session must be able to consume that refresh
# instead of failing while both bounded fetches are still legitimate.
LOCK_TIMEOUT = FETCH_TIMEOUT * 2 + 10
CANONICAL_REPOSITORY = "jpawlowski/opnsense-openid-connect"
CANONICAL_FETCH_URL = f"https://github.com/{CANONICAL_REPOSITORY}.git"
READ_ONLY_PUSH_URL = "disabled://canonical-upstream-is-read-only"
SNAPSHOT_WARNING = (
    "No Git remote is available in this isolated checkout; remote freshness and push access cannot be verified. "
    "Use the cloud platform's existing-PR update path or hand a commit or patch to the integrating agent."
)


def event_input():
    content = sys.stdin.read()
    return json.loads(content) if content.strip() else {}


def state_paths(event):
    identity = f"{REPOSITORY}\0{event.get('session_id', 'unknown')}".encode()
    key = hashlib.sha256(identity).hexdigest()
    directory = Path(tempfile.gettempdir()) / "opnsense-openid-connect-agent-hooks"
    return directory / f"{key}.json", directory / f"{key}.log"


def git_output(*arguments):
    return subprocess.run(
        ("git", *arguments, "--", *RELEVANT_PATHS),
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


def repository_git(repository, *arguments, check=True, timeout=None):
    return subprocess.run(
        ("git", *arguments),
        cwd=repository,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def git_value(repository, *arguments):
    result = repository_git(repository, *arguments, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def github_repository(url):
    """Return owner/repository for the GitHub URL forms Git commonly uses."""
    value = url.strip()
    if value.startswith("git@github.com:"):
        path = value.removeprefix("git@github.com:")
    else:
        parsed = urlparse(value)
        if parsed.hostname != "github.com":
            return None
        path = parsed.path
    parts = path.strip("/").removesuffix(".git").split("/")
    if len(parts) != 2 or not all(parts):
        return None
    return "/".join(parts).lower()


def execution_context(repository, environment=None):
    """Identify cloud execution without depending on undocumented vendor state."""
    environment = os.environ if environment is None else environment
    configured = environment.get("AGENT_EXECUTION", "").strip().lower()
    if configured in ("codex-cloud", "claude-cloud", "copilot-cloud", "cloud"):
        return configured
    if environment.get("CLAUDE_CODE_REMOTE", "").strip().lower() == "true":
        return "claude-cloud"
    if environment.get("GITHUB_COPILOT_GIT_TOKEN") or environment.get("GITHUB_COPILOT_API_TOKEN"):
        return "copilot-cloud"
    if not git_value(repository, "remote", "get-url", "origin"):
        return "isolated-snapshot"
    return "local"


def ensure_remote_topology(repository):
    """Choose the canonical base without confusing a contributor fork with it."""
    origin_url = git_value(repository, "remote", "get-url", "origin")
    execution = execution_context(repository)
    if not origin_url:
        return {
            "base_remote": "",
            "base_ref": "",
            "base_name": "checkout snapshot",
            "fetch_remotes": (),
            "identity": f"snapshot\0{execution}",
            "fork": False,
            "remote_available": False,
            "execution": execution,
        }

    identity = github_repository(origin_url)
    if identity in (None, CANONICAL_REPOSITORY):
        return {
            "base_remote": "origin",
            "base_ref": "refs/remotes/origin/main",
            "base_name": "origin/main",
            "fetch_remotes": ("origin",),
            "identity": f"origin\0{origin_url}",
            "fork": False,
            "remote_available": True,
            "execution": execution,
        }

    upstream_url = git_value(repository, "remote", "get-url", "upstream")
    if upstream_url and github_repository(upstream_url) != CANONICAL_REPOSITORY:
        raise RuntimeError(
            f"remote 'upstream' already points to {upstream_url}; it was not replaced with {CANONICAL_FETCH_URL}"
        )
    if not upstream_url:
        repository_git(repository, "remote", "add", "upstream", CANONICAL_FETCH_URL)

    # A contributor publishes through origin. The canonical remote must never
    # become an accidental push target, even when credentials allow a push.
    repository_git(repository, "config", "--local", "--unset-all", "remote.upstream.pushurl", check=False)
    repository_git(repository, "config", "--local", "--add", "remote.upstream.pushurl", READ_ONLY_PUSH_URL)
    repository_git(
        repository, "config", "--local", "--replace-all", "remote.upstream.fetch",
        "+refs/heads/*:refs/remotes/upstream/*",
    )
    return {
        "base_remote": "upstream",
        "base_ref": "refs/remotes/upstream/main",
        "base_name": "upstream/main",
        "fetch_remotes": ("upstream", "origin"),
        "identity": f"upstream\0{origin_url}\0{CANONICAL_FETCH_URL}",
        "fork": True,
        "remote_available": True,
        "execution": execution,
    }


def common_git_directory(repository):
    path = Path(git_value(repository, "rev-parse", "--git-common-dir"))
    return path.resolve() if path.is_absolute() else (repository / path).resolve()


class RepositoryLock:
    """Serialize shared config, FETCH_HEAD and ref updates across worktrees."""

    def __init__(self, repository, timeout=LOCK_TIMEOUT):
        self.path = common_git_directory(repository) / "opnsense-agent-sync.lock"
        self.timeout = timeout
        self.acquired = False

    def __enter__(self):
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            try:
                self.path.mkdir()
                self.acquired = True
                return self
            except FileExistsError:
                # Fetches have their own short timeout. Leave enough margin for
                # both fork remotes and the ref update before treating an empty
                # lock as debris from an interrupted hook.
                try:
                    stale = time.time() - self.path.stat().st_mtime > LOCK_TIMEOUT + FETCH_TIMEOUT
                except FileNotFoundError:
                    stale = False
                if stale:
                    try:
                        self.path.rmdir()
                    except OSError:
                        pass
                time.sleep(0.05)
        raise TimeoutError("another agent is still synchronizing the shared repository")

    def __exit__(self, exception_type, exception, traceback):
        if self.acquired:
            self.path.rmdir()


def configure_repository(repository):
    """Install worktree-local commit guidance before an agent changes files."""
    # Repository-local configuration is otherwise shared by every linked
    # worktree. Absolute template paths must instead follow the active tree.
    repository_git(repository, "config", "--local", "extensions.worktreeConfig", "true")
    settings = (
        ("commit.template", str(repository / ".gitmessage")),
        ("core.hooksPath", "packaging/hooks"),
    )
    for key, value in settings:
        repository_git(repository, "config", "--worktree", key, value)


def sync_state_path(repository):
    return common_git_directory(repository) / "opnsense-agent-sync.json"


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def checked_out_main(repository):
    path = None
    for line in git_value(repository, "worktree", "list", "--porcelain").splitlines():
        if line.startswith("worktree "):
            path = Path(line.removeprefix("worktree "))
        elif line == "branch refs/heads/main":
            return path
    return None


def fast_forward_main(repository, base_ref, base_name, base_main):
    local_main = git_value(repository, "rev-parse", "--verify", "refs/heads/main")
    if not base_main:
        return f"{base_name} does not exist after the fetch"
    if local_main == base_main:
        return ""
    if local_main and repository_git(
        repository, "merge-base", "--is-ancestor", local_main, base_main, check=False,
    ).returncode != 0:
        return f"local main has commits outside {base_name} and was not changed"

    main_worktree = checked_out_main(repository)
    if main_worktree is not None:
        if git_value(main_worktree, "status", "--porcelain"):
            return f"the main control worktree at {main_worktree} is not clean and was not changed"
        repository_git(main_worktree, "merge", "--ff-only", base_ref)
        return ""

    arguments = ["update-ref", "refs/heads/main", base_main]
    if local_main:
        arguments.append(local_main)
    repository_git(repository, *arguments)
    return ""


def synchronize_repository(repository, max_age, required=False):
    """Refresh the canonical base once for all worktrees and safely mirror main."""
    with RepositoryLock(repository):
        configure_repository(repository)
        topology = ensure_remote_topology(repository)
        path = sync_state_path(repository)
        state = load_json(path)
        now = time.time()
        if not topology["remote_available"]:
            base_main = str(state.get("snapshot_base") or git_value(repository, "rev-parse", "HEAD"))
            state.update({
                "attempted_at": now,
                "topology": topology["identity"],
                "snapshot_base": base_main,
            })
            save_json(path, state)
            return {
                "fetched": False,
                "old_base": base_main,
                "base_main": base_main,
                "base_name": topology["base_name"],
                "fork": False,
                "warning": SNAPSHOT_WARNING,
                "remote_available": False,
                "execution": topology["execution"],
            }

        last_attempt = float(state.get("attempted_at", 0))
        old_base = git_value(repository, "rev-parse", "--verify", topology["base_ref"])
        fetched = False
        warning = str(state.get("error", ""))
        topology_changed = state.get("topology") != topology["identity"]

        if required or topology_changed or now - last_attempt >= max_age:
            state["attempted_at"] = now
            state["topology"] = topology["identity"]
            errors = []
            for remote in topology["fetch_remotes"]:
                try:
                    result = repository_git(
                        repository, "fetch", "--atomic", "--prune", remote,
                        check=False, timeout=FETCH_TIMEOUT,
                    )
                    if result.returncode != 0:
                        errors.append(f"{remote}: {result.stderr.strip() or 'git fetch failed'}")
                    elif remote == topology["base_remote"]:
                        fetched = True
                except subprocess.TimeoutExpired:
                    errors.append(f"{remote}: git fetch exceeded {FETCH_TIMEOUT} seconds")
            warning = "; ".join(errors)
            if warning:
                state["error"] = warning
            else:
                state["fetched_at"] = now
                state.pop("error", None)
            save_json(path, state)

        if warning and required:
            raise RuntimeError(f"{topology['base_name']} could not be refreshed: {warning}")

        new_base = git_value(repository, "rev-parse", "--verify", topology["base_ref"])
        main_warning = fast_forward_main(
            repository, topology["base_ref"], topology["base_name"], new_base,
        )
        warnings = [message for message in (warning, main_warning) if message]
        return {
            "fetched": fetched,
            "old_base": old_base,
            "base_main": new_base,
            "base_name": topology["base_name"],
            "fork": topology["fork"],
            "warning": "; ".join(warnings),
            "remote_available": True,
            "execution": topology["execution"],
        }


def fingerprint():
    digest = hashlib.sha256()
    digest.update(git_output("status", "--porcelain=v1", "-z", "--untracked-files=all"))
    digest.update(git_output("diff", "--binary", "--no-ext-diff", "HEAD"))

    untracked = git_output("ls-files", "-z", "--others", "--exclude-standard")
    for encoded_path in filter(None, untracked.split(b"\0")):
        path = REPOSITORY / os.fsdecode(encoded_path)
        digest.update(encoded_path)
        digest.update(str(path.lstat().st_mode & 0o111).encode())
        if path.is_symlink():
            digest.update(b"symlink\0" + os.fsencode(os.readlink(path)))
            continue
        digest.update(b"file\0")
        with path.open("rb") as source:
            for block in iter(lambda: source.read(128 * 1024), b""):
                digest.update(block)

    return digest.hexdigest()


def load_state(path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(path, state):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state), encoding="utf-8")
    temporary.replace(path)


def path_output(repository, *arguments):
    output = repository_git(repository, *arguments).stdout
    return {line for line in output.splitlines() if line}


def work_paths(repository, base_main):
    found = set()
    base = git_value(repository, "merge-base", "HEAD", base_main) if base_main else ""
    if base:
        found.update(path_output(repository, "diff", "--name-only", f"{base}..HEAD", "--"))
    found.update(path_output(repository, "diff", "--name-only", "--"))
    found.update(path_output(repository, "diff", "--cached", "--name-only", "--"))
    found.update(path_output(repository, "ls-files", "--others", "--exclude-standard"))
    return found


def main_progress(repository, state, base_main, base_name):
    base = state.get("base_main")
    seen = state.get("seen_main")
    if not base or not base_main or base_main in (base, seen):
        return ""

    changed = path_output(repository, "diff", "--name-only", f"{base}..{base_main}", "--")
    overlap = sorted(changed & work_paths(repository, base_main))
    count = git_value(repository, "rev-list", "--count", f"{base}..{base_main}") or "unknown"
    state["seen_main"] = base_main
    if overlap:
        preview = ", ".join(overlap[:8])
        suffix = ", …" if len(overlap) > 8 else ""
        return (
            f"{base_name} advanced by {count} commit(s) since this task began and overlaps this work in: "
            f"{preview}{suffix}. Refresh and integrate deliberately before publishing; no merge or rebase was run."
        )
    return (
        f"{base_name} advanced by {count} commit(s) since this task began without a changed-path overlap. "
        "The working branch was left unchanged."
    )


def branch_lag(repository, base_main, base_name):
    branch = git_value(repository, "symbolic-ref", "--short", "HEAD")
    if not branch or branch == "main" or not base_main:
        return ""
    count = git_value(repository, "rev-list", "--count", f"HEAD..{base_main}")
    if not count or count == "0":
        return ""
    return (
        f"The current branch {branch} is {count} commit(s) behind {base_name}. "
        "It was not rebased or merged automatically."
    )


def messages(*values):
    return " ".join(value for value in values if value)


def emit(value):
    json.dump(value, sys.stdout)
    sys.stdout.write("\n")


def informational(message):
    if not message:
        return {}
    if execution_context(REPOSITORY) == "copilot-cloud":
        return {"additionalContext": message}
    return {"systemMessage": message}


def initialize(event):
    synchronization = synchronize_repository(REPOSITORY, START_FETCH_TTL)
    state_path, _ = state_paths(event)
    state = load_state(state_path)
    if state is None:
        state = {
            "passed": fingerprint(),
            "failed": None,
            "base_main": synchronization["base_main"],
            "seen_main": synchronization["base_main"],
        }
    else:
        state.setdefault("base_main", synchronization["base_main"])
        state.setdefault("seen_main", synchronization["base_main"])
    save_state(state_path, state)

    branch = git_value(REPOSITORY, "symbolic-ref", "--short", "HEAD")
    branch_warning = ""
    if synchronization["execution"] == "local" and branch in ("", "main"):
        branch_warning = "Agent changes need their own topic branch and worktree; do not edit main or a detached HEAD."
    elif not synchronization["remote_available"] and branch in ("", "main"):
        branch_warning = (
            "This cloud or bundled snapshot may remain detached, but its commit is only a handoff artifact until "
            "the platform updates the existing pull request or an integrating agent applies it."
        )
    lag_warning = branch_lag(REPOSITORY, synchronization["base_main"], synchronization["base_name"])
    notice = messages(synchronization["warning"], branch_warning, lag_warning)
    emit(informational(notice))


def cleanup(event):
    for path in state_paths(event):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def failed_output(event, log_path, extra=""):
    reason = (
        "The fast host-independent checks failed. Fix the failure and run ./tests/run.sh again. "
        f"The complete output is in {log_path}. Integration and browser E2E tests were not run."
    )
    reason = messages(extra, reason)
    if event.get("stop_hook_active"):
        return {"systemMessage": reason}
    return {"decision": "block", "reason": reason}


def stop(event):
    synchronization = synchronize_repository(REPOSITORY, ACTIVE_FETCH_TTL)
    state_path, log_path = state_paths(event)
    state = load_state(state_path)
    current = fingerprint()

    # A hook added during an existing task has no trustworthy earlier baseline.
    if state is None:
        state = {
            "passed": current,
            "failed": None,
            "base_main": synchronization["base_main"],
            "seen_main": synchronization["base_main"],
        }
        save_state(state_path, state)
        emit(informational(synchronization["warning"]))
        return

    progress = main_progress(
        REPOSITORY, state, synchronization["base_main"], synchronization["base_name"],
    )
    notice = messages(synchronization["warning"], progress)
    save_state(state_path, state)

    if current == state["passed"]:
        emit(informational(notice))
        return

    if current == state.get("failed"):
        emit(failed_output(event, log_path, notice))
        return

    log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with log_path.open("wb") as output:
        result = subprocess.run(
            (str(REPOSITORY / "tests" / "run.sh"),),
            cwd=REPOSITORY,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )

    if result.returncode == 0:
        state.update({"passed": current, "failed": None})
        save_state(state_path, state)
        log_path.unlink(missing_ok=True)
        emit(informational(notice))
        return

    state["failed"] = current
    save_state(state_path, state)
    emit(failed_output(event, log_path, notice))


def refresh(event):
    synchronization = synchronize_repository(REPOSITORY, 0, required=True)
    state_path, _ = state_paths(event)
    state = load_state(state_path) or {
        "passed": fingerprint(), "failed": None,
        "base_main": synchronization["base_main"],
        "seen_main": synchronization["base_main"],
    }
    state.setdefault("base_main", synchronization["base_main"])
    state.setdefault("seen_main", synchronization["base_main"])
    progress = main_progress(
        REPOSITORY, state, synchronization["base_main"], synchronization["base_name"],
    )
    save_state(state_path, state)
    base = synchronization["base_main"][:12] if synchronization["base_main"] else "unavailable"
    if synchronization["warning"]:
        status = f"{synchronization['base_name']} is {base}; {synchronization['warning']}"
    else:
        status = f"{synchronization['base_name']} is {base}; local main is a safe fast-forward mirror."
    emit(informational(messages(status, progress)))


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    event = event_input()
    if action == "initialize":
        initialize(event)
    elif action == "stop":
        stop(event)
    elif action == "cleanup":
        cleanup(event)
    elif action == "refresh":
        refresh(event)
    else:
        raise ValueError(f"unknown hook action: {action}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # The agent must get a chance to diagnose a broken gate.
        if len(sys.argv) == 2 and sys.argv[1] == "stop":
            emit({"decision": "block", "reason": f"The fast test hook failed: {error}"})
        else:
            raise
