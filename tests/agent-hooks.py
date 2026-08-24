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
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from harness import check, group  # noqa: E402
import harness  # noqa: E402


def load_hook():
    spec = importlib.util.spec_from_file_location("fast_gate", ROOT / ".agents" / "hooks" / "fast_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_agent_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
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
    pre_tool = configuration["hooks"]["PreToolUse"][0]
    check("the guard observes shell, patch and delegated-agent tools",
          all(name in pre_tool["matcher"] for name in ("Bash", "apply_patch", "Agent")), True)
    check("the guard has enough time for one bounded refresh", pre_tool["hooks"][0]["timeout"], 60)
    check("supporting subagents receive read-only context",
          "SubagentStart" in configuration["hooks"], True)
    stop_timeout = configuration["hooks"]["Stop"][0]["hooks"][0]["timeout"]
    check("the Stop hook allows two bounded fetches and the test gate", stop_timeout, 120)
    check("SessionEnd can wait for a serialized cleanup decision",
          configuration["hooks"]["SessionEnd"][0]["hooks"][0]["timeout"], 60)
    copilot = json.loads((ROOT / ".github" / "hooks" / "agent-hygiene.json").read_text(encoding="utf-8"))
    copilot_hooks = [hook for hooks in copilot["hooks"].values() for hook in hooks]
    check("Copilot's schema adapter uses only the shared implementation",
          all(".agents/hooks/fast_gate.py" in hook["bash"] for hook in copilot_hooks), True)
    check("Copilot receives the same bounded SessionStart timeout",
          copilot["hooks"]["SessionStart"][0]["timeoutSec"], start_timeout)
    check("Copilot runs the same write guard before mutating tools",
          (copilot["hooks"]["PreToolUse"][0]["bash"], copilot["hooks"]["PreToolUse"][0]["matcher"]),
          ("python3 .agents/hooks/fast_gate.py guard", "Bash|Edit|Write|Agent|Task"))
    check("Copilot applies the shared read-only subagent context",
          copilot["hooks"]["SubagentStart"][0]["bash"], "python3 .agents/hooks/fast_gate.py subagent")
    check("Copilot receives the same bounded Stop timeout", copilot["hooks"]["Stop"][0]["timeoutSec"], 120)
    adapter_readme = (ROOT / ".github" / "hooks" / "README.md").read_text(encoding="utf-8")
    check("the strict Copilot adapter has an adjacent copyright exception",
          "Copyright (C) 2026 Julian Pawlowski" in adapter_readme and "strict hook" in adapter_readme, True)

    group("An agent task prepares its clone")
    hook = load_hook()
    original_execution_context = hook.execution_context
    hook.execution_context = lambda repository, environment=None: "copilot-cloud"
    check("Copilot receives a native top-level guard decision",
          hook.platform_output(hook.agent_guard.blocked("claim required")), {
              "permissionDecision": "deny", "permissionDecisionReason": "claim required",
          })
    hook.execution_context = original_execution_context
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
        hook.observe_remote = lambda task_state, synchronization: ("", "")
        sweep_arguments = []
        hook.worktree_cleanup.sweep = lambda *arguments, **keywords: sweep_arguments.append(keywords) or []
        hook.initialize({})
        check("session startup installs the local settings", configured, [hook.REPOSITORY])
        check("startup limits removals without starving later cleanup records",
              sweep_arguments, [{"current_path": hook.REPOSITORY, "max_removals": 1}])

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
        late_overlap = {"base_main": agent_head, "seen_main": agent_head}
        first_notice = hook.main_progress(worktree, late_overlap, remote_head, "origin/main")
        check("canonical progress is initially non-overlapping", "without a changed-path overlap" in first_notice,
              True)
        late_overlap["acknowledged_main"] = remote_head
        late_overlap["acknowledged_main_paths"] = late_overlap["main_paths_fingerprint"]
        (worktree / "remote.txt").write_text("agent later touched it\n", encoding="utf-8")
        late_notice = hook.main_progress(worktree, late_overlap, remote_head, "origin/main")
        check("the same canonical head is re-evaluated when local paths later overlap",
              "remote.txt" in late_notice and late_overlap.get("pending_main") == remote_head, True)
        check("an acknowledgement for the earlier path set cannot excuse a later overlap",
              "acknowledge-main" in hook.pending_main_refusal(
                  worktree, late_overlap, remote_head, "origin/main",
              ), True)
        (worktree / "remote.txt").unlink()
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
        drift_state = {
            "base_main": remote_head, "seen_main": remote_head,
        }
        progress = hook.main_progress(worktree, drift_state, refused["base_main"], refused["base_name"])
        check("overlapping remote and agent paths are called out", "shared.txt" in progress, True)
        check("progress identifies the selected canonical ref", "origin/main advanced" in progress, True)
        check("overlapping canonical progress becomes pending",
              drift_state["pending_main"], refused["base_main"])
        check("pending overlap blocks another write",
              "acknowledge-main" in hook.pending_main_refusal(
                  worktree, drift_state, refused["base_main"], refused["base_name"],
              ), True)
        drift_state["acknowledged_main"] = refused["base_main"]
        drift_state["acknowledged_main_paths"] = drift_state["main_paths_fingerprint"]
        check("a deliberate deferral releases the write guard",
              hook.pending_main_refusal(
                  worktree, drift_state, refused["base_main"], refused["base_name"],
              ), "")
        check("observing remote progress never rewrites the agent branch", subprocess.run(
            ("git", "rev-parse", "HEAD"), cwd=worktree, check=True, capture_output=True, text=True,
        ).stdout.strip(), agent_head)
        lag = hook.branch_lag(worktree, refused["base_main"], refused["base_name"])
        check("a stale topic branch is reported without rewriting it", "commit(s) behind origin/main" in lag, True)

    group("The local control checkout is readable but not writable by agents")
    guard_module = load_agent_module(
        "agent_guard_test", ROOT / ".agents" / "hooks" / "agent_guard.py",
    )
    check("searches are read-only", guard_module.is_read_only_shell("rg worktree AGENTS.md"), True)
    check("a newline cannot append a mutating command to a read-only search",
          guard_module.is_read_only_shell("rg worktree AGENTS.md\nrm tracked-file"), False)
    check("an escaped newline cannot manufacture an executable option",
          guard_module.is_read_only_shell("rg --pre\\\n=rm worktree tracked-file"), False)
    check("ripgrep preprocessors are not read-only",
          guard_module.is_read_only_shell("rg --pre=rm worktree tracked-file"), False)
    check("shell expansion cannot manufacture a ripgrep preprocessor option",
          guard_module.is_read_only_shell("rg ${UNSET:---pre=rm} worktree tracked-file"), False)
    check("brace expansion cannot manufacture a ripgrep preprocessor option",
          guard_module.is_read_only_shell("rg {--pre=rm,--hidden} worktree tracked-file"), False)
    check("pathname expansion cannot manufacture an executable option",
          guard_module.is_read_only_shell("rg --* worktree tracked-file"), False)
    check("quoted search syntax remains literal and readable",
          guard_module.is_read_only_shell("rg '[a-z]+\\?' AGENTS.md"), True)
    check("ripgrep hostname programs are not read-only",
          guard_module.is_read_only_shell("rg --hostname-bin sh worktree AGENTS.md"), False)
    check("environment overrides cannot alter an allow-listed program",
          guard_module.is_read_only_shell("RIPGREP_CONFIG_PATH=config rg worktree AGENTS.md"), False)
    previous_rg_config = os.environ.get("RIPGREP_CONFIG_PATH")
    os.environ["RIPGREP_CONFIG_PATH"] = "/tmp/untrusted-ripgrep-config"
    check("ambient ripgrep configuration makes bare inspection unsafe",
          guard_module.is_read_only_shell("rg worktree AGENTS.md"), False)
    check("--no-config suppresses ambient ripgrep configuration",
          guard_module.is_read_only_shell("rg --no-config worktree AGENTS.md"), True)
    if previous_rg_config is None:
        os.environ.pop("RIPGREP_CONFIG_PATH", None)
    else:
        os.environ["RIPGREP_CONFIG_PATH"] = previous_rg_config
    check("bare Git status may refresh the index",
          guard_module.is_read_only_shell("git --no-pager status --short"), False)
    check("Git status is read-only when optional index locks are disabled",
          guard_module.is_read_only_shell("GIT_OPTIONAL_LOCKS=0 git --no-pager status --short"), True)
    check("Git inspection cannot inherit helpers from another repository through -C",
          guard_module.is_read_only_shell("git -C /tmp/other --no-pager status --short"), False)
    check("a later paginate flag cannot re-enable a configured Git pager",
          guard_module.is_read_only_shell("git --no-pager --paginate log -1"), False)
    previous_git_pager = os.environ.get("GIT_PAGER")
    os.environ["GIT_PAGER"] = "touch pager-ran"
    check("an environment-selected Git pager makes bare inspection unsafe",
          guard_module.is_read_only_shell("git log -1"), False)
    check("--no-pager suppresses an environment-selected Git pager",
          guard_module.is_read_only_shell("GIT_OPTIONAL_LOCKS=0 git --no-pager log -1"), True)
    if previous_git_pager is None:
        os.environ.pop("GIT_PAGER", None)
    else:
        os.environ["GIT_PAGER"] = previous_git_pager
    check("a subcommand patch flag is not mistaken for a global Git pager",
          guard_module.is_read_only_shell("GIT_OPTIONAL_LOCKS=0 git --no-pager diff -p"), True)
    check("command-line Git configuration cannot install a read helper",
          guard_module.is_read_only_shell(
              "git --no-pager -c core.fsmonitor=/tmp/helper status --short",
          ), False)
    check("remote inspection must explicitly avoid querying the transport",
          guard_module.is_read_only_shell("git remote show origin"), False)
    check("remote inspection with no query is read-only",
          guard_module.is_read_only_shell("GIT_OPTIONAL_LOCKS=0 git --no-pager remote show -n origin"), True)
    check("a path-qualified look-alike Git executable is not trusted",
          guard_module.is_read_only_shell("/tmp/git status --short"), False)
    check("Git grep cannot launch a pager command",
          guard_module.is_read_only_shell("git grep --open-files-in-pager=rm needle"), False)
    check("Git diff cannot launch an external diff helper",
          guard_module.is_read_only_shell("git diff --ext-diff"), False)
    check("GitHub pull request inspection is read-only",
          guard_module.is_read_only_shell("gh pr view 42 --json headRefOid"), True)
    check("GitHub inspection cannot launch a configured browser helper",
          guard_module.is_read_only_shell("gh pr view 42 --web"), False)
    check("assigned GitHub browser flags are also rejected",
          guard_module.is_read_only_shell("gh pr view 42 --web=true"), False)
    check("GitHub API GET inspection is read-only",
          guard_module.is_read_only_shell("gh api repos/example/project/pulls/42"), True)
    check("the worktree bootstrap is an allowed control operation",
          guard_module.is_read_only_shell(
              "python3 .agents/worktrees.py create example --client codex",
          ), True)
    check("a look-alike helper outside the repository is not trusted",
          guard_module.is_read_only_shell("python3 /tmp/.agents/worktrees.py list"), False)
    check("the issue claim helper is an allowed coordination operation",
          guard_module.is_read_only_shell("python3 .agents/issues.py claim 42"), True)
    check("issue creation may bootstrap public coordination before a claim",
          guard_module.is_issue_bootstrap({
              "tool_name": "Bash", "tool_input": {"command": "gh issue create --title example"},
          }), True)
    check("issue bootstrap cannot target another repository",
          guard_module.is_issue_bootstrap({
              "tool_name": "Bash",
              "tool_input": {"command": "gh issue create --repo other/project --title example"},
          }), False)
    check("attached repository selectors cannot bypass issue-bootstrap scope",
          guard_module.is_issue_bootstrap({
              "tool_name": "Bash", "tool_input": {"command": "gh issue create -Rother/project -t example"},
          }), False)
    check("issue bootstrap cannot launch a configured browser helper",
          guard_module.is_issue_bootstrap({
              "tool_name": "Bash", "tool_input": {"command": "gh issue create --web"},
          }), False)
    check("assigned issue-bootstrap browser flags are also rejected",
          guard_module.is_issue_bootstrap({
              "tool_name": "Bash", "tool_input": {"command": "gh issue create --web=true"},
          }), False)
    check("issue bootstrap cannot launch a configured editor helper",
          guard_module.is_issue_bootstrap({
              "tool_name": "Bash", "tool_input": {"command": "gh issue create --editor"},
          }), False)
    check("shell redirection is not read-only", guard_module.is_read_only_shell("rg value . > result"), False)
    check("bounded sed line inspection remains read-only",
          guard_module.is_read_only_shell("sed -n 1,20p AGENTS.md"), True)
    check("a sed write command is not disguised as inspection",
          guard_module.is_read_only_shell("sed -n 'w leaked.txt' AGENTS.md"), False)
    check("in-place editing is not read-only", guard_module.is_read_only_shell("sed -i old new file"), False)
    check("long in-place editing is not read-only",
          guard_module.is_read_only_shell("sed --in-place old new file"), False)
    check("Git checkout is not read-only", guard_module.is_read_only_shell("git checkout other"), False)
    check("a mutating option cannot hide behind Git branch listing",
          guard_module.is_read_only_shell("git branch --list -D old"), False)
    check("a forced Git branch update cannot hide behind listing",
          guard_module.is_read_only_shell("git branch --list --force old HEAD"), False)
    check("a mutating option cannot hide behind Git config listing",
          guard_module.is_read_only_shell("git config --list --unset user.name"), False)
    check("a mutating remote command cannot hide behind verbose output",
          guard_module.is_read_only_shell("git remote -v add other example.invalid/repo"), False)
    check("a compound command fails closed", guard_module.is_read_only_shell("git status && git diff"), False)
    check("an unclassified test command fails closed", guard_module.is_read_only_shell("./tests/run.sh"), False)
    check("Git push forces an uncached remote observation", guard_module.requires_uncached_remote({
        "tool_name": "Bash", "tool_input": {"command": "git push origin codex/topic"},
    }), True)
    check("Git global options cannot hide a push boundary", guard_module.requires_uncached_remote({
        "tool_name": "Bash", "tool_input": {"command": "git -C . push origin codex/topic"},
    }), True)
    check("a Git alias cannot hide a push boundary", guard_module.requires_uncached_remote({
        "tool_name": "Bash",
        "tool_input": {"command": "git -c alias.publish=push publish origin codex/topic"},
    }), True)
    check("the command builtin cannot hide a push boundary", guard_module.requires_uncached_remote({
        "tool_name": "Bash", "tool_input": {"command": "command git push origin codex/topic"},
    }), True)
    check("a path-qualified Git executable fails closed at a publication boundary",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash", "tool_input": {"command": "/usr/bin/git push origin codex/topic"},
          }), True)
    check("an environment wrapper cannot hide a push boundary", guard_module.requires_uncached_remote({
        "tool_name": "Bash", "tool_input": {"command": "env GIT_OPTIONAL_LOCKS=0 git push origin codex/topic"},
    }), True)
    check("an external command wrapper cannot hide a push boundary",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash", "tool_input": {"command": "timeout 10 git push origin codex/topic"},
          }), True)
    check("an opaque flock command string cannot hide a push boundary",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash",
              "tool_input": {"command": "flock /tmp/lock -c 'git push origin codex/topic'"},
          }), True)
    check("an unlisted outer program cannot hide a visible nested Git executable",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash",
              "tool_input": {"command": "launcher --quiet git push origin codex/topic"},
          }), True)
    check("a leading environment assignment cannot hide a push boundary",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash", "tool_input": {"command": "FOO=bar git push origin codex/topic"},
          }), True)
    check("GitHub CLI publication forces an uncached remote observation", guard_module.requires_uncached_remote({
        "tool_name": "Bash", "tool_input": {"command": "gh pr ready"},
    }), True)
    check("GitHub API mutation forces an uncached remote observation", guard_module.requires_uncached_remote({
        "tool_name": "Bash", "tool_input": {"command": "gh api --method PATCH repos/example/project/pulls/42"},
    }), True)
    check("a detached worktree needs a branch before commit", guard_module.requires_topic_branch({
        "tool_name": "Bash", "tool_input": {"command": "git commit -m 'test: durable work'"},
    }), True)
    check("Git global options cannot hide a detached-worktree commit", guard_module.requires_topic_branch({
        "tool_name": "Bash", "tool_input": {"command": "git -C . commit -m 'test: durable work'"},
    }), True)
    check("a Git alias cannot hide a detached-worktree commit", guard_module.requires_topic_branch({
        "tool_name": "Bash", "tool_input": {"command": "git -c alias.save=commit save -m test"},
    }), True)
    check("the exec builtin cannot hide a detached-worktree commit", guard_module.requires_topic_branch({
        "tool_name": "Bash", "tool_input": {"command": "exec git commit -m 'test: durable work'"},
    }), True)
    check("a leading environment assignment cannot hide a detached-worktree commit",
          guard_module.requires_topic_branch({
              "tool_name": "Bash", "tool_input": {"command": "FOO=bar git commit -m test"},
          }), True)
    check("an unlisted launcher cannot hide a detached-worktree commit",
          guard_module.requires_topic_branch({
              "tool_name": "Bash", "tool_input": {"command": "flock /tmp/lock git commit -m test"},
          }), True)
    check("an opaque flock command string cannot hide a detached-worktree commit",
          guard_module.requires_topic_branch({
              "tool_name": "Bash", "tool_input": {"command": "flock /tmp/lock -c 'git commit -m test'"},
          }), True)
    check("an opaque execution wrapper fails closed even around nested read-only Git",
          guard_module.requires_topic_branch({
              "tool_name": "Bash", "tool_input": {"command": "flock /tmp/lock git status --short"},
          }), True)
    check("a shell interpreter cannot hide a push boundary", guard_module.requires_uncached_remote({
        "tool_name": "Bash", "tool_input": {"command": "bash -c 'git push origin codex/topic'"},
    }), True)
    check("a shell control list fails closed at a publication boundary",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash", "tool_input": {"command": "true; git push origin codex/topic"},
          }), True)
    check("a subshell fails closed at a publication boundary",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash", "tool_input": {"command": "(git push origin codex/topic)"},
          }), True)
    check("quoted commit punctuation cannot hide a detached-worktree commit", guard_module.requires_topic_branch({
        "tool_name": "Bash", "tool_input": {"command": "git commit -m 'test: durable work?'"},
    }), True)
    check("an expanded Git subcommand fails closed at a publication boundary",
          guard_module.requires_uncached_remote({
              "tool_name": "Bash", "tool_input": {"command": "git ${ACTION}"},
          }), True)
    check("ordinary detached worktree tests need no branch", guard_module.requires_topic_branch({
        "tool_name": "Bash", "tool_input": {"command": "./tests/run.sh"},
    }), False)
    check("a delegated read-only marker is required", guard_module.is_read_only_agent({
        "tool_input": {"message": "[read-only] inspect the protocol"},
    }), True)
    check("an unmarked delegated task is not read-only", guard_module.is_read_only_agent({
        "tool_input": {"message": "implement the protocol"},
    }), False)

    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        control = root / "control"
        linked = root / "linked"
        subprocess.run(("git", "init", "-b", "main", "-q", str(control)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=control, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=control, check=True)
        subprocess.run((
            "git", "remote", "add", "origin", "https://github.com/jpawlowski/opnsense-openid-connect.git",
        ), cwd=control, check=True)
        (control / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", "base.txt"), cwd=control, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=control, check=True)
        subprocess.run(("git", "worktree", "add", "-q", "-b", "codex/test", str(linked)),
                       cwd=control, check=True)

        original_repository_root = guard_module.REPOSITORY_ROOT
        guard_module.REPOSITORY_ROOT = control
        subprocess.run(("git", "config", "core.fsmonitor", "/tmp/untrusted-fsmonitor"), cwd=control, check=True)
        check("a configured fsmonitor makes Git status unsafe in the control checkout",
              guard_module.is_read_only_shell("git --no-pager status --short"), False)
        subprocess.run(("git", "config", "core.fsmonitor", "false"), cwd=control, check=True)
        subprocess.run(("git", "config", "diff.external", "/tmp/untrusted-diff"), cwd=control, check=True)
        check("a configured external diff helper is not read-only",
              guard_module.is_read_only_shell("git --no-pager diff"), False)
        check("an explicitly disabled external diff remains read-only",
              guard_module.is_read_only_shell(
                  "GIT_OPTIONAL_LOCKS=0 git --no-pager diff --no-ext-diff",
              ), True)
        subprocess.run(("git", "config", "--unset", "diff.external"), cwd=control, check=True)
        guard_module.REPOSITORY_ROOT = original_repository_root

        check("the primary checkout is recognized", guard_module.is_primary_worktree(control), True)
        check("a linked worktree is isolated", guard_module.is_primary_worktree(linked), False)
        subprocess.run(("git", "checkout", "--detach", "-q"), cwd=linked, check=True)
        check("a detached linked worktree remains isolated", guard_module.is_primary_worktree(linked), False)

        check("the first writer acquires a clean worktree",
              guard_module.acquire_lease(linked, "session-one", now=0), "")
        check("the same writer refreshes its lease",
              guard_module.acquire_lease(linked, "session-one", now=1), "")
        check("another live writer is refused",
              "another writing task" in guard_module.acquire_lease(linked, "session-two", now=2), True)
        check("a stale clean lease can be taken over",
              guard_module.acquire_lease(linked, "session-two", now=guard_module.LEASE_TTL + 2), "")
        guard_module.release_lease(linked, "session-two")

        check("a clean worktree can be leased again",
              guard_module.acquire_lease(linked, "session-one", now=0), "")
        (linked / "dirty.txt").write_text("dirty\n", encoding="utf-8")
        check("a stale dirty worktree is never taken over",
              "dirty worktree" in guard_module.acquire_lease(
                  linked, "session-two", now=guard_module.LEASE_TTL + 1,
              ), True)
        guard_module.release_lease(linked, "session-one")
        check("ending a dirty task preserves its resumable ownership",
              guard_module.read_lease(linked).get("session_id"), "session-one")
        check("the same task can resume its dirty worktree",
              guard_module.acquire_lease(linked, "session-one", now=guard_module.LEASE_TTL + 2), "")
        (linked / "dirty.txt").unlink()
        guard_module.release_lease(linked, "session-one")

        hook = load_hook()
        hook.REPOSITORY = control
        emitted = []
        hook.emit = emitted.append
        hook.guard({"session_id": "primary", "tool_name": "apply_patch", "tool_input": {"command": "patch"}})
        check("a patch in the control checkout is blocked",
              emitted[0]["hookSpecificOutput"]["permissionDecision"], "deny")
        emitted.clear()
        hook.guard({
            "session_id": "primary", "tool_name": "Bash",
            "tool_input": {"command": "gh issue create --title coordination"},
        })
        check("the control checkout may create the issue needed before implementation", emitted[0], {})
        acknowledgement_state = root / "acknowledgement-state.json"
        acknowledgement_state.write_text(json.dumps({
            "pending_main": "abcdef1234567890", "main_paths_fingerprint": "paths",
        }), encoding="utf-8")
        hook.state_paths = lambda event: (acknowledgement_state, acknowledgement_state.with_suffix(".log"))
        emitted.clear()
        hook.guard({
            "session_id": "primary", "tool_name": "Bash",
            "tool_input": {"command": (
                "python3 .agents/hooks/fast_gate.py acknowledge-main "
                "--sha abcdef123456 --reason 'reviewed overlap'"
            )},
        })
        acknowledged = json.loads(acknowledgement_state.read_text(encoding="utf-8"))
        check("the trusted helper records a deliberate main-drift acknowledgement",
              (emitted[0], acknowledged.get("acknowledged_main")), ({}, "abcdef1234567890"))
        emitted.clear()
        hook.guard({
            "session_id": "primary", "tool_name": "Bash",
            "tool_input": {"command": "rm acknowledge-main --sha abcdef123456 --reason bypass"},
        })
        check("acknowledgement-looking operands cannot bypass the control checkout",
              emitted[0]["hookSpecificOutput"]["permissionDecision"], "deny")

        hook = load_hook()
        hook.REPOSITORY = linked
        hook.synchronize_repository = lambda repository, max_age, required=False: {
            "base_main": "base", "old_base": "base", "base_name": "origin/main",
            "warning": "", "remote_available": True, "execution": "local",
        }
        hook.observe_remote = lambda state, synchronization, **_keywords: ("", "")
        state = root / "guard-state.json"
        hook.state_paths = lambda event: (state, state.with_suffix(".log"))
        emitted = []
        hook.emit = emitted.append
        hook.guard({
            "session_id": "writer-one", "tool_name": "Bash",
            "tool_input": {"command": "git commit -m 'test: detached'"},
        })
        check("a durable commit is blocked while the isolated worktree is detached",
              emitted[0]["hookSpecificOutput"]["permissionDecision"], "deny")
        emitted.clear()
        hook.guard({"session_id": "writer-one", "tool_name": "apply_patch", "tool_input": {"command": "patch"}})
        check("an isolated writer without a public issue claim is blocked",
              "No exclusive issue claim" in emitted[0]["hookSpecificOutput"]["permissionDecisionReason"], True)
        hook.issue_claim.save_registry(linked, {
            "version": 1,
            "claims": {str(linked.resolve()): {
                "issue": 42, "status": "active", "token": "test-claim", "worktree_marker": True,
            }},
        })
        hook.issue_claim.write_marker(linked, "test-claim")
        emitted.clear()
        hook.guard({"session_id": "writer-one", "tool_name": "apply_patch", "tool_input": {"command": "patch"}})
        check("a claimed writer in an isolated clean worktree is allowed", emitted[0], {})
        hook.guard({"session_id": "writer-two", "tool_name": "apply_patch", "tool_input": {"command": "patch"}})
        check("a second worktree writer is blocked",
              emitted[1]["hookSpecificOutput"]["permissionDecision"], "deny")
        subprocess.run(("git", "switch", "-q", "codex/test"), cwd=linked, check=True)
        hook.synchronize_repository = lambda repository, max_age, required=False: (
            (_ for _ in ()).throw(RuntimeError("canonical fetch failed")) if required else {
                "base_main": "base", "old_base": "base", "base_name": "origin/main",
                "warning": "", "remote_available": True, "execution": "local",
            }
        )
        emitted.clear()
        hook.guard({
            "session_id": "writer-one", "tool_name": "Bash",
            "tool_input": {"command": "git -C . push origin codex/test"},
        })
        check("a failed canonical fetch blocks publication",
              "canonical fetch failed" in emitted[0]["hookSpecificOutput"]["permissionDecisionReason"], True)
        remote_head = "a" * 40
        hook.synchronize_repository = lambda repository, max_age, required=False: {
            "base_main": "base", "old_base": "base", "base_name": "origin/main",
            "warning": "", "remote_available": True, "execution": "local",
        }
        hook.observe_remote = lambda state, synchronization, **keywords: (
            "", "" if keywords.get("reconciled_pr_head") == remote_head else "foreign pull-request head",
        )
        emitted.clear()
        hook.guard({
            "session_id": "writer-one", "tool_name": "Bash",
            "tool_input": {"command": (
                "python3 .agents/hooks/fast_gate.py reconcile-pr "
                f"--sha {remote_head} --strategy merge"
            )},
        })
        check("the exact trusted helper can reconcile the freshly observed pull-request head", emitted[0], {})
        emitted.clear()
        hook.guard({
            "session_id": "writer-one", "tool_name": "Bash",
            "tool_input": {"command": (
                "python3 .agents/hooks/fast_gate.py reconcile-pr "
                f"--sha {'b' * 40} --strategy merge"
            )},
        })
        check("a reconciliation request for any other head remains blocked",
              "foreign pull-request head" in emitted[0]["hookSpecificOutput"]["permissionDecisionReason"], True)
        hook.synchronize_repository = lambda repository, max_age, required=False: {
            "base_main": "snapshot", "old_base": "snapshot", "base_name": "snapshot HEAD",
            "warning": "remote freshness unavailable", "remote_available": False, "execution": "codex-cloud",
        }
        hook.observe_remote = lambda state, synchronization, **keywords: ("", "")
        emitted.clear()
        hook.guard({
            "session_id": "writer-one", "tool_name": "Bash",
            "tool_input": {"command": (
                "git push https://github.com/jpawlowski/opnsense-openid-connect.git "
                "HEAD:codex/test"
            )},
        })
        check("a remote-less snapshot cannot publish through an explicit Git URL",
              "no observable Git remote" in emitted[0]["hookSpecificOutput"]["permissionDecisionReason"], True)
        emitted.clear()
        hook.guard({"session_id": "writer-one", "tool_name": "Handoff", "tool_input": {}})
        check("a remote-less snapshot can still hand its commit to an integrating agent",
              ("permissionDecision" in emitted[0].get("hookSpecificOutput", {}), emitted[0].get("systemMessage")),
              (False, "remote freshness unavailable"))
        guard_module.release_lease(linked, "writer-one")

    group("Issue claims are unique, race-safe and completely temporary")
    claim_module = load_agent_module(
        "issue_claim_test", ROOT / ".agents" / "hooks" / "issue_claim.py",
    )
    with tempfile.TemporaryDirectory() as temporary:
        repository = pathlib.Path(temporary) / "repository"
        subprocess.run(("git", "init", "-b", "codex/claimed", "-q", str(repository)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=repository, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=repository, check=True)
        subprocess.run((
            "git", "remote", "add", "origin", "https://github.com/jpawlowski/opnsense-openid-connect.git",
        ), cwd=repository, check=True)
        (repository / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", "base.txt"), cwd=repository, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=repository, check=True)
        concurrent_update = """
import importlib.util
from pathlib import Path
import sys
import time

spec = importlib.util.spec_from_file_location("claim_worker", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
repository = Path(sys.argv[2])
key = sys.argv[3]

def update(registry):
    registry["claims"][key] = {"issue": key}
    time.sleep(0.2)

module.update_registry(repository, update)
"""
        workers = [
            subprocess.Popen((
                sys.executable, "-c", concurrent_update, str(ROOT / ".agents" / "hooks" / "issue_claim.py"),
                str(repository), key,
            ))
            for key in ("first-worktree", "second-worktree")
        ]
        worker_results = [worker.wait() for worker in workers]
        check("parallel worktrees serialize claim-registry read-modify-write cycles",
              (worker_results, sorted(claim_module.load_registry(repository)["claims"])),
              ([0, 0], ["first-worktree", "second-worktree"]))
        claim_module.save_registry(repository, {"version": 1, "claims": {}})
        issue = {
            "number": 36, "state": "OPEN", "labels": [], "comments": [], "assignees": [],
            "closedByPullRequestsReferences": [], "url": "https://example.invalid/issues/36",
        }
        label_definitions = set()
        issue_state = {
            "fail_after_comment": False, "comment_published": False,
            "head_repository": "jpawlowski/opnsense-openid-connect",
        }

        def issue_copy(_number):
            if issue_state["fail_after_comment"] and issue_state["comment_published"]:
                issue_state["fail_after_comment"] = False
                raise RuntimeError("temporary issue verification failure")
            return json.loads(json.dumps(issue))

        def fake_gh(arguments, json_output=False):
            arguments = tuple(arguments)
            if arguments[:2] == ("api", "user"):
                return "publisher"
            if arguments[:2] == ("api", "repos/jpawlowski/opnsense-openid-connect/labels"):
                label = next(value.removeprefix("name=") for value in arguments if value.startswith("name="))
                if label in label_definitions:
                    raise RuntimeError("label already exists")
                label_definitions.add(label)
                return {"name": label}
            if arguments[:2] == ("label", "create"):
                label_definitions.add(arguments[2])
                return ""
            if arguments[:2] == ("label", "delete"):
                label_definitions.discard(arguments[2])
                issue["labels"] = [value for value in issue["labels"] if value["name"] != arguments[2]]
                return ""
            if arguments[:2] == ("issue", "edit"):
                if "--add-label" in arguments:
                    label = arguments[arguments.index("--add-label") + 1]
                    issue["labels"].append({"name": label})
                if "--remove-label" in arguments:
                    label = arguments[arguments.index("--remove-label") + 1]
                    issue["labels"] = [value for value in issue["labels"] if value["name"] != label]
                if "--add-assignee" in arguments:
                    login = arguments[arguments.index("--add-assignee") + 1]
                    if not any(value.get("login") == login for value in issue["assignees"]):
                        issue["assignees"].append({"login": login})
                if "--remove-assignee" in arguments:
                    login = arguments[arguments.index("--remove-assignee") + 1]
                    issue["assignees"] = [
                        value for value in issue["assignees"] if value.get("login") != login
                    ]
                return ""
            if arguments[:2] == ("issue", "comment"):
                body = arguments[arguments.index("--body") + 1]
                token = claim_module.CLAIM_PATTERN.search(body).group(1)
                database_id = 9000 + len(issue["comments"]) + 1
                issue["comments"].append({
                    "body": body, "id": f"comment-{token}",
                    "databaseId": database_id,
                    "url": f"https://example.invalid/issues/36#issuecomment-{database_id}",
                    "createdAt": "2026-08-24T00:00:00Z",
                })
                issue_state["comment_published"] = True
                return issue["comments"][-1]["url"]
            if arguments[:3] == ("api", "-X", "DELETE"):
                database_id = int(arguments[3].rsplit("/", 1)[1])
                issue["comments"] = [
                    value for value in issue["comments"] if value.get("databaseId") != database_id
                ]
                return ""
            if arguments[:2] == ("api", "graphql"):
                comment_id = next(value.removeprefix("id=") for value in arguments if value.startswith("id="))
                issue["comments"] = [value for value in issue["comments"] if value["id"] != comment_id]
                return ""
            if arguments[:2] == ("pr", "view"):
                return {
                    "number": 41, "state": "OPEN", "body": "Fixes #36",
                    "headRefName": "codex/claimed",
                    "headRefOid": subprocess.run(
                        ("git", "rev-parse", "HEAD"), cwd=repository, check=True,
                        capture_output=True, text=True,
                    ).stdout.strip(),
                    "headRepository": {"nameWithOwner": issue_state["head_repository"]},
                    "url": "https://example.invalid/pulls/41",
                }
            raise AssertionError(arguments)

        claim_module._issue = issue_copy
        claim_module._gh = fake_gh
        issue_state["fail_after_comment"] = True
        try:
            claim_module.claim(repository, 36, now=1_776_999_999)
            verification_failed = False
        except RuntimeError:
            verification_failed = True
        check("a failed verification removes its already-published claim comment",
              (verification_failed, issue["comments"], issue["labels"], issue["assignees"], label_definitions),
              (True, [], [], [], set()))
        issue["assignees"] = [{"login": "publisher"}]
        issue_state.update({"fail_after_comment": True, "comment_published": False})
        try:
            claim_module.claim(repository, 36, now=1_776_999_999)
        except RuntimeError:
            pass
        check("failed verification preserves a pre-existing assignee",
              issue["assignees"], [{"login": "publisher"}])
        issue_state.update({"fail_after_comment": False, "comment_published": False})
        claim_module.claim(repository, 36, now=1_776_999_999)
        claim_module.release(repository)
        check("releasing a successful claim preserves a pre-existing assignee",
              issue["assignees"], [{"login": "publisher"}])
        issue["assignees"] = []
        claimed = claim_module.claim(repository, 36, now=1_777_000_000)
        check("the WIP label embeds the claim timestamp",
              claimed["label"].startswith("wip:1777000000-"), True)
        check("the marker and issue label carry the same unique id",
              claimed["token"] in issue["comments"][0]["body"]
              and issue["labels"] == [{"name": claimed["label"]}], True)
        try:
            claim_module._acquire_lock(36, "competing-token")
            lock_was_exclusive = False
        except RuntimeError:
            lock_was_exclusive = True
        check("the fixed per-issue label definition is an atomic cross-clone lock", lock_was_exclusive, True)
        try:
            claim_module.adopt_pull_request(repository, 41)
            adopted_over_claim = True
        except RuntimeError:
            adopted_over_claim = False
        check("adoption cannot overwrite an active issue claim",
              (adopted_over_claim, bool(issue["comments"]), bool(issue["labels"])), (False, True, True))
        claim_module.marker_path(repository).unlink()
        check("a reused worktree path cannot trust a claim without its private marker",
              claim_module.current_claim(repository), None)
        claim_module.write_marker(repository, claimed["token"])
        linked_claim = claim_module.linked(repository, 41)
        check("the linked pull request replaces the issue lock", linked_claim["status"], "pr-linked")
        check("linking deletes the comment, issue label and repository label definition",
              (issue["comments"], issue["labels"], label_definitions), ([], [], set()))
        subprocess.run(("git", "switch", "-q", "-c", "codex/unrelated"), cwd=repository, check=True)
        check("a PR-linked claim cannot authorize a different branch",
              claim_module.current_claim(repository), None)
        subprocess.run(("git", "switch", "-q", "codex/claimed"), cwd=repository, check=True)
        check("the linked claim remains valid on its bound branch and descendants",
              claim_module.current_claim(repository)["pull_request"], 41)
        try:
            claim_module.claim(repository, 37, now=1_777_000_001)
            replaced = True
        except RuntimeError:
            replaced = False
        check("one worktree cannot abandon its current claim by claiming another issue", replaced, False)
        claim_module.forget(repository)
        issue_state["head_repository"] = "other/fork"
        try:
            claim_module.adopt_pull_request(repository, 41)
            adopted_foreign_repository = True
        except RuntimeError:
            adopted_foreign_repository = False
        check("a pull request from another repository cannot be adopted",
              (adopted_foreign_repository, claim_module.current_claim(repository)), (False, None))
        issue_state["head_repository"] = "jpawlowski/opnsense-openid-connect"
        issue["assignees"] = []
        released_claim = claim_module.claim(repository, 37, now=1_777_000_001)
        claim_module.release(repository)
        check("stopping before a pull request removes every public and local claim artifact",
              (released_claim["label"] in label_definitions, issue["comments"], issue["labels"], issue["assignees"],
               claim_module.current_claim(repository)), (False, [], [], [], None))

    group("Open pull requests are observed without mutating GitHub")
    watch = load_agent_module(
        "github_watch_test", ROOT / ".agents" / "hooks" / "github_watch.py",
    )
    with tempfile.TemporaryDirectory() as temporary:
        repository = pathlib.Path(temporary) / "repository"
        subprocess.run(("git", "init", "-b", "codex/watch", "-q", str(repository)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=repository, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=repository, check=True)
        subprocess.run((
            "git", "remote", "add", "origin", "https://github.com/jpawlowski/opnsense-openid-connect.git",
        ), cwd=repository, check=True)
        (repository / "shared.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", "shared.txt"), cwd=repository, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=repository, check=True)
        head = subprocess.run(("git", "rev-parse", "HEAD"), cwd=repository, check=True,
                              capture_output=True, text=True).stdout.strip()
        calls = []

        def reader(_repository, path, _token):
            calls.append(path)
            if path.startswith("pulls?state=open"):
                return [
                    {"number": 1, "title": "Current", "html_url": "https://example.invalid/1", "draft": True,
                     "head": {"ref": "codex/watch", "sha": head,
                              "repo": {"full_name": "jpawlowski/opnsense-openid-connect"}}},
                    {"number": 2, "title": "Other", "html_url": "https://example.invalid/2", "draft": False,
                     "head": {"ref": "codex/other", "sha": "other",
                              "repo": {"full_name": "jpawlowski/opnsense-openid-connect"}}},
                ]
            if path.startswith("pulls/1/files") or path.startswith("pulls/2/files"):
                return [{"filename": "shared.txt"}]
            if path == "pulls/1":
                return {"html_url": "https://example.invalid/1", "draft": True, "mergeable": True,
                        "mergeable_state": "clean", "head": {"sha": head}}
            if path.startswith("pulls/1/reviews"):
                return [{"user": {"login": "reviewer"}, "state": "APPROVED", "commit_id": head}]
            if path.startswith(f"commits/{head}/check-runs"):
                return {"check_runs": [{"status": "completed", "conclusion": "success"}]}
            if path == f"commits/{head}/status":
                return {"state": "success"}
            raise AssertionError(f"unexpected GitHub path {path}")

        watch.github_token = lambda environment=None: ""
        watch.github_graphql = lambda owner, name, number, token: None
        snapshot, warning = watch.refresh(
            repository, repository / ".git", "jpawlowski/opnsense-openid-connect",
            max_age=0, now=10, reader=reader,
        )
        check("the public fallback returned no warning", warning, "")
        check("the current pull request is matched by branch and repository",
              snapshot["current"]["number"], 1)
        check("checks and reviews are summarized",
              (snapshot["current"]["checks"], snapshot["current"]["review_decision"]),
              ("passing", "approved"))
        check("a pending legacy status keeps completed check runs pending", watch._check_state(
            {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            {"state": "pending", "statuses": [{"context": "legacy", "state": "pending"}]},
        ), "pending")
        check("the empty combined-status default does not hide successful check runs", watch._check_state(
            {"check_runs": [{"status": "completed", "conclusion": "success"}]},
            {"state": "pending", "statuses": []},
        ), "passing")
        check("an approval on an older head is stale", watch._review_decision([
            {"user": {"login": "reviewer"}, "state": "APPROVED", "commit_id": "older"},
        ], head), "stale approval")
        check("unavailable review threads remain explicitly unknown",
              snapshot["current"]["unresolved_threads"], None)
        check("a pull request leaving the open set ends the waiting phase",
              "closed or merged" in watch.state_notice(snapshot["current"], None), True)
        check("another open pull request reports changed-path overlap",
              "#2" in watch.overlap_notice(snapshot, {"shared.txt"}), True)
        check("the matching remote head is safe", watch.remote_head_refusal(repository, snapshot), "")
        reused = watch.branch_pull_state(
            "jpawlowski/opnsense-openid-connect", "jpawlowski/opnsense-openid-connect",
            "codex/watch", head,
            reader=lambda _repository, _path, _token: [
                {"number": 8, "state": "closed", "merged_at": "2026-08-01T00:00:00Z",
                 "head": {"ref": "codex/watch", "sha": head,
                          "repo": {"full_name": "jpawlowski/opnsense-openid-connect"}}},
                {"number": 9, "state": "open", "merged_at": None,
                 "head": {"ref": "codex/watch", "sha": "foreign",
                          "repo": {"full_name": "jpawlowski/opnsense-openid-connect"}}},
            ],
        )
        check("an open reused branch head outranks an exact historical merged pull request",
              (reused["state"], reused["number"]), ("foreign-head", 9))
        first_calls = len(calls)
        cached, warning = watch.refresh(
            repository, repository / ".git", "jpawlowski/opnsense-openid-connect",
            max_age=watch.PR_REFRESH_TTL, now=11, reader=reader,
        )
        check("a fresh task-local PR snapshot is reused", len(calls), first_calls)
        check("the cached snapshot keeps its current pull request", cached["current"]["number"], 1)
        def failed_reader(_repository, _path, _token):
            raise ValueError("temporary GitHub failure")

        stale, warning = watch.refresh(
            repository, repository / ".git", "jpawlowski/opnsense-openid-connect",
            max_age=0, now=12, reader=failed_reader,
        )
        check("a failed refresh identifies its cached snapshot as stale",
              (stale["current"]["number"], warning), (1, "temporary GitHub failure"))

        publication_hook = load_hook()
        publication_hook.REPOSITORY = repository
        publication_hook.github_watch.refresh = lambda *_arguments, **_keywords: (
            stale, "temporary GitHub failure",
        )
        _notice, refusal = publication_hook.observe_remote(
            {"base_main": head, "seen_main": head},
            {
                "base_main": head, "base_name": "origin/main", "remote_available": True,
            },
            pr_max_age=0, require_pr_fresh=True,
        )
        check("a stale GitHub snapshot blocks a publication boundary",
              "Fresh GitHub state is unavailable" in refusal, True)
        tree = subprocess.run(("git", "rev-parse", "HEAD^{tree}"), cwd=repository, check=True,
                              capture_output=True, text=True).stdout.strip()
        foreign = subprocess.run(("git", "commit-tree", tree, "-p", head, "-m", "test: foreign"),
                                 cwd=repository, check=True, capture_output=True, text=True).stdout.strip()
        snapshot["current"]["head_sha"] = foreign
        check("a foreign remote head blocks more local writing",
              "not contained" in watch.remote_head_refusal(repository, snapshot), True)

    group("Finished worktrees retire before local branches and never delete remote branches")
    cleanup = load_agent_module(
        "worktree_cleanup_test", ROOT / ".agents" / "hooks" / "worktree_cleanup.py",
    )
    cleanup.github_watch.github_token = lambda environment=None: ""
    with tempfile.TemporaryDirectory() as temporary:
        control = pathlib.Path(temporary) / "control"
        linked = pathlib.Path(temporary) / "linked"
        subprocess.run(("git", "init", "-b", "main", "-q", str(control)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=control, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=control, check=True)
        subprocess.run((
            "git", "remote", "add", "origin", "https://github.com/jpawlowski/opnsense-openid-connect.git",
        ), cwd=control, check=True)
        (control / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        (control / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", ".gitignore", "base.txt"), cwd=control, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=control, check=True)
        subprocess.run(("git", "worktree", "add", "-q", "-b", "codex/cleanup", str(linked)),
                       cwd=control, check=True)
        (linked / "feature.txt").write_text("feature\n", encoding="utf-8")
        subprocess.run(("git", "add", "feature.txt"), cwd=linked, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: feature"), cwd=linked, check=True)
        head = subprocess.run(("git", "rev-parse", "HEAD"), cwd=linked, check=True,
                              capture_output=True, text=True).stdout.strip()
        subprocess.run(("git", "update-ref", "refs/remotes/origin/codex/cleanup", head),
                       cwd=control, check=True)

        def merged_reader(_repository, path, _token):
            if path.startswith("pulls?"):
                return [{
                    "number": 17, "state": "closed", "merged_at": "2026-08-24T10:00:00Z",
                    "head": {"ref": "codex/cleanup", "sha": head,
                             "repo": {"full_name": "jpawlowski/opnsense-openid-connect"}},
                }]
            raise AssertionError(f"unexpected GitHub path {path}")

        cleanup.register(linked, client="codex", slug="cleanup", managed_by="repository", now=10)
        waiting = cleanup.finish_session(linked, "task-one", pull_number=17, now=20)
        check("an open pull request keeps its clean worktree", "still open" in waiting, True)
        registry = cleanup.load_registry(control)
        record = next(iter(registry["records"].values()))
        check("waiting work is not retired", bool(record.get("retired_at")), False)
        cleanup.sweep(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=21, reader=merged_reader,
        )
        registry = cleanup.load_registry(control)
        record = next(iter(registry["records"].values()))
        check("a merged waiting pull request enters retirement automatically", record["retired_at"], 21)
        retired = cleanup.finish_session(linked, "task-one", now=30)
        check("a clean completed session enters the cleanup queue", "queued" in retired, True)
        cleanup.register(linked, session_id="task-one", now=31)
        registry = cleanup.load_registry(control)
        record = next(iter(registry["records"].values()))
        check("resuming the same task cancels its pending retirement", bool(record.get("retired_at")), False)
        cleanup.finish_session(linked, "task-one", now=32)

        too_early = cleanup.inventory(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=32 + cleanup.WORKTREE_GRACE - 1, reader=merged_reader,
        )
        cleanup_record = next(value for value in too_early if value.get("branch") == "codex/cleanup")
        check("a retired worktree observes its safety grace period", cleanup_record["state"], "grace")
        current = cleanup.inventory(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=linked,
            now=32 + cleanup.WORKTREE_GRACE + 1, reader=merged_reader,
        )
        cleanup_record = next(value for value in current if value.get("branch") == "codex/cleanup")
        check("a sweep never removes its current worktree", cleanup_record["state"], "active")

        (linked / "dirty.txt").write_text("dirty\n", encoding="utf-8")
        dirty = cleanup.inventory(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=32 + cleanup.WORKTREE_GRACE + 1, reader=merged_reader,
        )
        cleanup_record = next(value for value in dirty if value.get("branch") == "codex/cleanup")
        check("a dirty retired worktree remains blocked", cleanup_record["state"], "blocked")
        (linked / "dirty.txt").unlink()
        (linked / "ignored").mkdir()
        (linked / "ignored" / "artifact").write_text("generated\n", encoding="utf-8")
        ignored = cleanup.inventory(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=32 + cleanup.WORKTREE_GRACE + 1, reader=merged_reader,
        )
        cleanup_record = next(value for value in ignored if value.get("branch") == "codex/cleanup")
        check("ignored artifacts also block deletion", cleanup_record["reason"], "ignored files")
        (linked / "ignored" / "artifact").unlink()
        (linked / "ignored").rmdir()

        cleanup.issue_claim.save_registry(control, {
            "version": 1,
            "claims": {str(linked.resolve()): {"issue": 17, "status": "pr-linked"}},
        })

        actions = cleanup.sweep(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=32 + cleanup.WORKTREE_GRACE + 1, reader=merged_reader,
        )
        check("the first sweep removes only the clean worktree", actions,
              [f"removed worktree {linked.resolve()}; local branch retained"])
        check("worktree removal also forgets its completed local issue record",
              cleanup.issue_claim.load_registry(control)["claims"], {})
        check("the local topic branch remains after worktree cleanup", subprocess.run(
            ("git", "show-ref", "--verify", "refs/heads/codex/cleanup"), cwd=control, check=False,
            capture_output=True, text=True,
        ).returncode, 0)
        replacement = pathlib.Path(temporary) / "replacement"
        subprocess.run(("git", "worktree", "add", "-q", str(replacement), "codex/cleanup"),
                       cwd=control, check=True)
        actions = cleanup.sweep(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=32 + cleanup.BRANCH_GRACE + 1, reader=merged_reader,
        )
        check("a retained branch checked out in a replacement worktree is not deleted", actions, [])
        check("the replacement worktree keeps its attached branch", subprocess.run(
            ("git", "symbolic-ref", "--short", "HEAD"), cwd=replacement, check=True,
            capture_output=True, text=True,
        ).stdout.strip(), "codex/cleanup")
        subprocess.run(("git", "worktree", "remove", "--", str(replacement)), cwd=control, check=True)
        actions = cleanup.sweep(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=32 + cleanup.BRANCH_GRACE + 1, reader=merged_reader,
        )
        check("a later sweep deletes the exactly merged local branch", actions,
              ["deleted merged local branch codex/cleanup; no remote branch was changed"])
        check("the remote-tracking branch is never deleted", subprocess.run(
            ("git", "show-ref", "--verify", "refs/remotes/origin/codex/cleanup"), cwd=control, check=False,
            capture_output=True, text=True,
        ).returncode, 0)

        subprocess.run(("git", "branch", "codex/closed", "main"), cwd=control, check=True)
        cleanup.retire(control, "codex/closed", now=40)
        closed_head = subprocess.run(("git", "rev-parse", "codex/closed"), cwd=control, check=True,
                                     capture_output=True, text=True).stdout.strip()

        def closed_reader(_repository, path, _token):
            if path.startswith("pulls?"):
                return [{
                    "number": 18, "state": "closed", "merged_at": None,
                    "head": {"ref": "codex/closed", "sha": closed_head,
                             "repo": {"full_name": "jpawlowski/opnsense-openid-connect"}},
                }]
            raise AssertionError(f"unexpected GitHub path {path}")

        closed = cleanup.inventory(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=40 + cleanup.BRANCH_GRACE + 1, reader=closed_reader,
        )
        closed_record = next(value for value in closed if value.get("branch") == "codex/closed")
        check("a closed unmerged pull request blocks branch deletion", closed_record["state"], "blocked")

        subprocess.run(("git", "branch", "codex/foreign", "main"), cwd=control, check=True)
        cleanup.retire(control, "foreign", now=50)

        def foreign_reader(_repository, path, _token):
            if path.startswith("pulls?"):
                return [{
                    "number": 19, "state": "open", "merged_at": None,
                    "head": {"ref": "codex/foreign", "sha": "f" * 40,
                             "repo": {"full_name": "jpawlowski/opnsense-openid-connect"}},
                }]
            raise AssertionError(f"unexpected GitHub path {path}")

        foreign = cleanup.inventory(
            control, "main", "jpawlowski/opnsense-openid-connect", current_path=control,
            now=50 + cleanup.BRANCH_GRACE + 1, reader=foreign_reader,
        )
        foreign_record = next(value for value in foreign if value.get("branch") == "codex/foreign")
        check("a foreign pull-request head blocks branch deletion", foreign_record["state"], "blocked")

    group("The manual bootstrap creates an untracked topic branch from the canonical ref")
    worktree_module = load_agent_module("worktrees_test", ROOT / ".agents" / "worktrees.py")
    with tempfile.TemporaryDirectory() as temporary:
        control = pathlib.Path(temporary) / "project"
        subprocess.run(("git", "init", "-b", "main", "-q", str(control)), check=True)
        subprocess.run(("git", "config", "user.name", "Test"), cwd=control, check=True)
        subprocess.run(("git", "config", "user.email", "test"), cwd=control, check=True)
        (control / "base.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(("git", "add", "base.txt"), cwd=control, check=True)
        subprocess.run(("git", "commit", "-q", "-m", "test: seed"), cwd=control, check=True)
        subprocess.run(("git", "update-ref", "refs/remotes/origin/main", "HEAD"), cwd=control, check=True)
        head = subprocess.run(("git", "rev-parse", "HEAD"), cwd=control, check=True,
                              capture_output=True, text=True).stdout.strip()
        worktree_module.ROOT = control
        worktree_module.fast_gate.synchronize_repository = lambda repository, max_age, required=False: {
            "base_main": head, "base_name": "origin/main", "remote_available": True,
        }
        worktree_module.create(SimpleNamespace(slug="isolated", client="codex"))
        target = control.parent / "project-codex-isolated"
        check("the helper creates the deterministic sibling path", target.is_dir(), True)
        check("the helper creates the requested topic branch", subprocess.run(
            ("git", "symbolic-ref", "--short", "HEAD"), cwd=target, check=True,
            capture_output=True, text=True,
        ).stdout.strip(), "codex/isolated")
        check("the new topic branch does not track canonical main", subprocess.run(
            ("git", "rev-parse", "--abbrev-ref", "@{upstream}"), cwd=target, check=False,
            capture_output=True, text=True,
        ).returncode == 0, False)

    group("Explicit refresh reports the truth about local main")
    cleanup_hook = load_hook()
    check("an unavailable observation preserves a PR-linked worktree",
          cleanup_hook.cleanup_pull_number(
              {"pr_state": None}, {"status": "pr-linked", "pull_request": 41},
          ), 41)
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
        hook.observe_remote = lambda task_state, synchronization, **_keywords: ("", "")
        emitted = []
        hook.emit = emitted.append
        hook.refresh({})
        message = emitted[0]["systemMessage"]
        check("a refused main fast-forward surfaces its warning", "was not changed" in message, True)
        check("a refused main fast-forward is not called a safe mirror",
              "safe fast-forward mirror" in message, False)
        emitted.clear()
        hook.synchronize_repository = lambda repository, max_age, required=False: {
            "base_main": "abcdef1234567890", "old_base": "abcdef1234567890",
            "base_name": "origin/main", "warning": "", "remote_available": True, "execution": "local",
        }
        hook.watch({})
        check("an unchanged waiting monitor remains silent", emitted[0], {})


if __name__ == "__main__":
    harness.run(main)
