#!/usr/bin/env python3
#
# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Run the small deterministic test tier once per relevant workspace state."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


REPOSITORY = Path(__file__).resolve().parents[2]
RELEVANT_PATHS = (
    ".codex",
    ".forgejo/workflows",
    ".github/workflows",
    "LICENSE",
    "packaging",
    "src",
    "tests",
)


def event_input():
    return json.load(sys.stdin)


def state_paths(event):
    identity = f"{REPOSITORY}\0{event.get('session_id', 'unknown')}".encode()
    key = hashlib.sha256(identity).hexdigest()
    directory = Path(tempfile.gettempdir()) / "codex-opnsense-openid-connect-hooks"
    return directory / f"{key}.json", directory / f"{key}.log"


def git_output(*arguments):
    return subprocess.run(
        ("git", *arguments, "--", *RELEVANT_PATHS),
        cwd=REPOSITORY,
        check=True,
        stdout=subprocess.PIPE,
    ).stdout


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


def emit(value):
    json.dump(value, sys.stdout)
    sys.stdout.write("\n")


def initialize(event):
    state_path, _ = state_paths(event)
    if not state_path.exists():
        save_state(state_path, {"passed": fingerprint(), "failed": None})


def cleanup(event):
    for path in state_paths(event):
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def failed_output(event, log_path):
    reason = (
        "The fast host-independent checks failed. Fix the failure and run ./tests/run.sh again. "
        f"The complete output is in {log_path}. Integration and browser E2E tests were not run."
    )
    if event.get("stop_hook_active"):
        return {"systemMessage": reason}
    return {"decision": "block", "reason": reason}


def stop(event):
    state_path, log_path = state_paths(event)
    state = load_state(state_path)
    current = fingerprint()

    # A hook added during an existing task has no trustworthy earlier baseline.
    if state is None:
        save_state(state_path, {"passed": current, "failed": None})
        emit({})
        return

    if current == state["passed"]:
        emit({})
        return

    if current == state.get("failed"):
        emit(failed_output(event, log_path))
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
        save_state(state_path, {"passed": current, "failed": None})
        log_path.unlink(missing_ok=True)
        emit({})
        return

    save_state(state_path, {"passed": state["passed"], "failed": current})
    emit(failed_output(event, log_path))


def main():
    action = sys.argv[1] if len(sys.argv) == 2 else ""
    event = event_input()
    if action == "initialize":
        initialize(event)
    elif action == "stop":
        stop(event)
    elif action == "cleanup":
        cleanup(event)
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
