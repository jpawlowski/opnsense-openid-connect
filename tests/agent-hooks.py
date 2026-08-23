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
    group("Codex, Claude and Copilot share their hook implementation")
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
    start_timeout = configuration["hooks"]["SessionStart"][0]["hooks"][0]["timeout"]
    check("SessionStart allows both bounded fork fetches", start_timeout, 60)
    stop_timeout = configuration["hooks"]["Stop"][0]["hooks"][0]["timeout"]
    check("the Stop hook allows two bounded fetches and the test gate", stop_timeout, 120)
    copilot = json.loads((ROOT / ".github" / "hooks" / "agent-hygiene.json").read_text(encoding="utf-8"))
    copilot_hooks = [hook for hooks in copilot["hooks"].values() for hook in hooks]
    check("Copilot's schema adapter uses only the shared implementation",
          all(".agents/hooks/fast_gate.py" in hook["bash"] for hook in copilot_hooks), True)
    check("Copilot receives the same bounded SessionStart timeout",
          copilot["hooks"]["SessionStart"][0]["timeoutSec"], start_timeout)
    check("Copilot receives the same bounded Stop timeout", copilot["hooks"]["Stop"][0]["timeoutSec"], 120)
    adapter_readme = (ROOT / ".github" / "hooks" / "README.md").read_text(encoding="utf-8")
    check("the strict Copilot adapter has an adjacent copyright exception",
          "Copyright (C) 2026 Julian Pawlowski" in adapter_readme and "strict hook" in adapter_readme, True)

    group("An agent task prepares its clone")
    hook = load_hook()
    check("parallel sessions wait longer than two bounded fork fetches",
          hook.LOCK_TIMEOUT > hook.FETCH_TIMEOUT * 2, True)
    check("classifier scripts participate in the Stop fingerprint",
          ".github/scripts" in hook.RELEVANT_PATHS, True)
    with tempfile.TemporaryDirectory() as temporary:
        state = pathlib.Path(temporary) / "existing-state.json"
        state.write_text("{}", encoding="utf-8")
        configured = []
        hook.configure_repository = configured.append
        hook.synchronize_repository = lambda repository, max_age: (
            hook.configure_repository(repository) or {
                "base_main": "base", "base_name": "origin/main", "warning": "", "fetched": False,
                "remote_available": True, "execution": "local",
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

    group("Forks get one safe canonical upstream")
    hook = load_hook()
    check("HTTPS canonical URLs are recognized",
          hook.github_repository("https://github.com/jpawlowski/opnsense-openid-connect.git"),
          hook.CANONICAL_REPOSITORY)
    check("scp-style SSH canonical URLs are recognized",
          hook.github_repository("git@github.com:jpawlowski/opnsense-openid-connect.git"),
          hook.CANONICAL_REPOSITORY)
    check("URI-style SSH canonical URLs are recognized",
          hook.github_repository("ssh://git@github.com/jpawlowski/opnsense-openid-connect.git"),
          hook.CANONICAL_REPOSITORY)
    check("Claude's documented cloud marker is recognized",
          hook.execution_context(ROOT, {"CLAUDE_CODE_REMOTE": "true"}), "claude-cloud")
    check("the repository-defined Codex cloud marker is recognized",
          hook.execution_context(ROOT, {"AGENT_EXECUTION": "codex-cloud"}), "codex-cloud")
    check("the repository-defined Copilot cloud marker is recognized",
          hook.execution_context(ROOT, {"AGENT_EXECUTION": "copilot-cloud"}), "copilot-cloud")
    check("Copilot's documented scoped Git token is recognized",
          hook.execution_context(ROOT, {"GITHUB_COPILOT_GIT_TOKEN": "present"}), "copilot-cloud")
    with tempfile.TemporaryDirectory() as temporary:
        snapshot = pathlib.Path(temporary) / "snapshot"
        subprocess.run(("git", "init", "-b", "main", "-q", str(snapshot)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=snapshot, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=snapshot, check=True)
        (snapshot / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", "base.txt"), cwd=snapshot, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=snapshot, check=True)
        topology = hook.ensure_remote_topology(snapshot)
        check("a remote-less cloud checkout is an isolated snapshot", topology["remote_available"], False)
        check("snapshot recognition never fabricates an origin",
              subprocess.run(("git", "remote"), cwd=snapshot, check=True, capture_output=True,
                             text=True).stdout, "")
        synchronized = hook.synchronize_repository(snapshot, 0, required=True)
        check("a snapshot refresh reports that remote freshness is unavailable",
              "cannot be verified" in synchronized["warning"], True)

        direct = pathlib.Path(temporary) / "direct"
        subprocess.run(("git", "init", "-q", str(direct)), check=True)
        subprocess.run((
            "git", "remote", "add", "origin", "git@github.com:jpawlowski/opnsense-openid-connect.git",
        ), cwd=direct, check=True)
        topology = hook.ensure_remote_topology(direct)
        check("a direct clone keeps origin as its canonical base", topology["base_name"], "origin/main")
        check("a direct clone does not gain an upstream remote",
              subprocess.run(("git", "remote"), cwd=direct, check=True, capture_output=True,
                             text=True).stdout.splitlines(), ["origin"])

        fork = pathlib.Path(temporary) / "fork"
        subprocess.run(("git", "init", "-q", str(fork)), check=True)
        subprocess.run((
            "git", "remote", "add", "origin", "https://github.com/contributor/fork.opnsense-openid-connect.git",
        ), cwd=fork, check=True)
        topology = hook.ensure_remote_topology(fork)
        check("a renamed GitHub fork uses upstream as its canonical base",
              topology["base_name"], "upstream/main")
        check("the canonical upstream is installed",
              local_config(fork, "remote.upstream.url", "--local"), hook.CANONICAL_FETCH_URL)
        check("the canonical upstream cannot be pushed",
              local_config(fork, "remote.upstream.pushurl", "--local"), hook.READ_ONLY_PUSH_URL)
        check("the contributor fork stays the publishing remote",
              local_config(fork, "remote.origin.url", "--local"),
              "https://github.com/contributor/fork.opnsense-openid-connect.git")

        conflict = pathlib.Path(temporary) / "conflict"
        subprocess.run(("git", "init", "-q", str(conflict)), check=True)
        subprocess.run((
            "git", "remote", "add", "origin", "https://github.com/contributor/project.git",
        ), cwd=conflict, check=True)
        wrong_upstream = "https://github.com/somewhere/else.git"
        subprocess.run(("git", "remote", "add", "upstream", wrong_upstream), cwd=conflict, check=True)
        try:
            hook.ensure_remote_topology(conflict)
            conflict_refused = False
        except RuntimeError:
            conflict_refused = True
        check("an occupied upstream name is refused", conflict_refused, True)
        check("an occupied upstream remote is never overwritten",
              local_config(conflict, "remote.upstream.url", "--local"), wrong_upstream)

    group("A fork follows canonical upstream rather than its own stale main")
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        upstream_remote = root / "upstream.git"
        fork_remote = root / "fork.git"
        seed = root / "seed"
        clone = root / "clone"
        worktree = root / "agent"
        for remote in (upstream_remote, fork_remote):
            subprocess.run(("git", "init", "--bare", "-q", str(remote)), check=True)
        subprocess.run(("git", "init", "-b", "main", "-q", str(seed)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=seed, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=seed, check=True)
        (seed / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", "base.txt"), cwd=seed, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=seed, check=True)
        for name, remote in (("upstream", upstream_remote), ("fork", fork_remote)):
            subprocess.run(("git", "remote", "add", name, str(remote)), cwd=seed, check=True)
            subprocess.run(("git", "push", "-q", name, "main"), cwd=seed, check=True)
            subprocess.run(("git", "symbolic-ref", "HEAD", "refs/heads/main"), cwd=remote, check=True)
        subprocess.run(("git", "clone", "-q", str(fork_remote), str(clone)), check=True)
        subprocess.run(("git", "remote", "add", "upstream", str(upstream_remote)), cwd=clone, check=True)
        subprocess.run(("git", "worktree", "add", "-q", "-b", "codex/fork", str(worktree), "origin/main"),
                       cwd=clone, check=True)
        topic_head = subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip()

        (seed / "canonical.txt").write_text("upstream only\n", encoding="utf-8")
        subprocess.run(("git", "add", "canonical.txt"), cwd=seed, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: advance canonical"), cwd=seed, check=True)
        subprocess.run(("git", "push", "-q", "upstream", "main"), cwd=seed, check=True)

        hook = load_hook()
        hook.ensure_remote_topology = lambda repository: {
            "base_remote": "upstream",
            "base_ref": "refs/remotes/upstream/main",
            "base_name": "upstream/main",
            "fetch_remotes": ("upstream", "origin"),
            "identity": "fork-test",
            "fork": True,
            "remote_available": True,
            "execution": "local",
        }
        synchronized = hook.synchronize_repository(worktree, 0, required=True)
        upstream_head = subprocess.run(
            ("git", "rev-parse", "upstream/main"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip()
        check("fork synchronization reports upstream/main", synchronized["base_name"], "upstream/main")
        check("fork synchronization follows canonical progress", synchronized["base_main"], upstream_head)
        check("the stale fork ref remains distinct", subprocess.run(
            ("git", "rev-parse", "origin/main"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip() == upstream_head, False)
        check("local main mirrors canonical upstream", subprocess.run(
            ("git", "rev-parse", "main"), cwd=clone, check=True, capture_output=True, text=True,
        ).stdout.strip(), upstream_head)
        check("canonical synchronization never rewrites the topic branch", subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip(), topic_head)

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
        check("one worktree fetch updates the shared origin/main", synchronized["base_main"], remote_head)
        check("a local non-GitHub remote remains the canonical base", synchronized["base_name"], "origin/main")
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
        }, refused["base_main"], refused["base_name"])
        check("overlapping remote and agent paths are called out", "shared.txt" in progress, True)
        check("progress identifies the selected canonical ref", "origin/main advanced" in progress, True)
        check("observing remote progress never rewrites the agent branch", subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip(), agent_head)
        lag = hook.branch_lag(worktree, refused["base_main"], refused["base_name"])
        check("a stale topic branch is reported without rewriting it", "commit(s) behind origin/main" in lag, True)

    group("Explicit refresh reports the truth about local main")
    with tempfile.TemporaryDirectory() as temporary:
        state = pathlib.Path(temporary) / "state.json"
        state.write_text(json.dumps({
            "passed": "same", "failed": None, "base_main": "abc", "seen_main": "abc",
        }), encoding="utf-8")
        hook = load_hook()
        hook.synchronize_repository = lambda repository, max_age, required=False: {
            "base_main": "abcdef1234567890",
            "base_name": "origin/main",
            "warning": "local main has commits outside origin/main and was not changed",
            "remote_available": True,
            "execution": "local",
        }
        hook.state_paths = lambda event: (state, state.with_suffix(".log"))
        hook.main_progress = lambda *arguments: ""
        emitted = []
        hook.emit = emitted.append
        hook.refresh({})
        message = emitted[0]["systemMessage"]
        check("a refused main fast-forward surfaces its warning", "was not changed" in message, True)
        check("a refused main fast-forward is not called a safe mirror",
              "safe fast-forward mirror" in message, False)


if __name__ == "__main__":
    harness.run(main)
