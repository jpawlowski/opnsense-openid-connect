#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
"""Checks the shared setup performed when a Codex or Claude task starts."""

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from harness import check, group  # noqa: E402
import harness  # noqa: E402


def load_hook():
    spec = importlib.util.spec_from_file_location("fast_gate", ROOT / ".agents" / "hooks" / "fast_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def local_config(repository, key, scope="--worktree"):
    return subprocess.run(
        ("git", "config", scope, "--get", key),
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def main():
    group("Codex and Claude share their hooks")
    shared = ROOT / ".agents" / "hooks.json"
    codex = ROOT / ".codex" / "hooks.json"
    claude = ROOT / ".claude" / "settings.json"
    check("Codex links to the shared configuration",
          codex.is_symlink() and os.readlink(codex) == "../.agents/hooks.json")
    check("Claude links to the shared configuration",
          claude.is_symlink() and os.readlink(claude) == "../.agents/hooks.json")
    claude_skills = ROOT / ".claude" / "skills"
    contribution = ROOT / ".agents" / "skills" / "github-contribution" / "SKILL.md"
    check("Claude links to every shared skill",
          claude_skills.is_symlink() and os.readlink(claude_skills) == "../.agents/skills")
    check("the public contribution procedure is shared", contribution.is_file())
    configuration = json.loads(shared.read_text(encoding="utf-8"))
    commands = [
        hook["command"]
        for matchers in configuration["hooks"].values()
        for matcher in matchers
        for hook in matcher["hooks"]
    ]
    check("every command uses the shared implementation",
          all("/.agents/hooks/fast_gate.py\"" in command for command in commands))

    group("An agent task prepares its clone")
    hook = load_hook()
    with tempfile.TemporaryDirectory() as temporary:
        state = pathlib.Path(temporary) / "existing-state.json"
        state.write_text("{}", encoding="utf-8")
        configured = []
        hook.configure_repository = configured.append
        hook.synchronize_repository = lambda repository, max_age: (
            hook.configure_repository(repository) or {
                "origin_main": "base", "warning": "", "fetched": False, "old_origin": "base",
            }
        )
        hook.state_paths = lambda event: (state, state.with_suffix(".log"))
        hook.initialize({})
        check("session startup installs the local settings", configured, [hook.REPOSITORY])

    with tempfile.TemporaryDirectory() as temporary:
        repository = pathlib.Path(temporary)
        subprocess.run(("git", "init", "-q", str(repository)), check=True)

        hook = load_hook()
        hook.configure_repository(repository)
        check("worktree-specific Git configuration is enabled",
              local_config(repository, "extensions.worktreeConfig", "--local"), "true")
        check("the commit editor uses the repository template",
              local_config(repository, "commit.template"), str(repository / ".gitmessage"))
        check("git finds the tracked commit hook",
              local_config(repository, "core.hooksPath"), "packaging/hooks")

        subprocess.run(("git", "config", "--worktree", "commit.template", "somewhere-else"),
                       cwd=repository, check=True)
        subprocess.run(("git", "config", "--worktree", "core.hooksPath", "somewhere-else"),
                       cwd=repository, check=True)
        hook.configure_repository(repository)
        check("a later task restores the template",
              local_config(repository, "commit.template"), str(repository / ".gitmessage"))
        check("a later task restores the hook path",
              local_config(repository, "core.hooksPath"), "packaging/hooks")

    group("Parallel worktrees share a remote view without sharing mutable setup")
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        remote = root / "remote.git"
        seed = root / "seed"
        clone = root / "clone"
        worktree = root / "agent"
        subprocess.run(("git", "init", "--bare", "-q", str(remote)), check=True)
        subprocess.run(("git", "init", "-b", "main", "-q", str(seed)), check=True)
        for repository in (seed,):
            subprocess.run(("git", "config", "user.name", "Test"), cwd=repository, check=True)
            subprocess.run(("git", "config", "user.email", "test"), cwd=repository, check=True)
        (seed / "shared.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", "shared.txt"), cwd=seed, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=seed, check=True)
        subprocess.run(("git", "remote", "add", "origin", str(remote)), cwd=seed, check=True)
        subprocess.run(("git", "push", "-q", "-u", "origin", "main"), cwd=seed, check=True)
        subprocess.run(("git", "symbolic-ref", "HEAD", "refs/heads/main"), cwd=remote, check=True)
        subprocess.run(("git", "clone", "-q", str(remote), str(clone)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=clone, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=clone, check=True)
        subprocess.run(("git", "worktree", "add", "-q", "-b", "codex/parallel", str(worktree), "origin/main"),
                       cwd=clone, check=True)

        hook = load_hook()
        hook.configure_repository(clone)
        hook.configure_repository(worktree)
        check("the main worktree keeps its own template path",
              local_config(clone, "commit.template"), str(clone / ".gitmessage"))
        check("the agent worktree keeps its own template path",
              local_config(worktree, "commit.template"), str(worktree / ".gitmessage"))

        (seed / "remote.txt").write_text("remote\n", encoding="utf-8")
        subprocess.run(("git", "add", "remote.txt"), cwd=seed, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: advance remote"), cwd=seed, check=True)
        subprocess.run(("git", "push", "-q"), cwd=seed, check=True)
        synchronized = hook.synchronize_repository(worktree, 0, required=True)
        remote_head = subprocess.run(
            ("git", "rev-parse", "origin/main"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip()
        check("one worktree fetch updates the shared origin/main", synchronized["origin_main"], remote_head)
        check("the clean local main control worktree fast-forwards", subprocess.run(
            ("git", "rev-parse", "main"), cwd=clone, check=True, capture_output=True, text=True,
        ).stdout.strip(), remote_head)

        (clone / "local.txt").write_text("local\n", encoding="utf-8")
        subprocess.run(("git", "add", "local.txt"), cwd=clone, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: diverge local main"), cwd=clone, check=True)
        local_head = subprocess.run(
            ("git", "rev-parse", "main"), cwd=clone, check=True, capture_output=True, text=True,
        ).stdout.strip()
        agent_head = subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip()
        (worktree / "shared.txt").write_text("agent\n", encoding="utf-8")
        (seed / "shared.txt").write_text("remote changed\n", encoding="utf-8")
        subprocess.run(("git", "add", "shared.txt"), cwd=seed, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: advance again"), cwd=seed, check=True)
        subprocess.run(("git", "push", "-q"), cwd=seed, check=True)
        refused = hook.synchronize_repository(worktree, 0, required=True)
        check("a divergent local main is reported rather than reset",
              "outside origin/main" in refused["warning"], True)
        check("the divergent local main commit remains untouched", subprocess.run(
            ("git", "rev-parse", "main"), cwd=clone, check=True, capture_output=True, text=True,
        ).stdout.strip(), local_head)
        progress = hook.main_progress(worktree, {
            "base_main": remote_head, "seen_main": remote_head,
        }, refused["origin_main"])
        check("overlapping remote and agent paths are called out", "shared.txt" in progress, True)
        check("observing remote progress never rewrites the agent branch", subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip(), agent_head)


if __name__ == "__main__":
    harness.run(main)
