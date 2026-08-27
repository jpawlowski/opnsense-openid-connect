#!/usr/bin/env python3

"""Keep local agent writers in one owned worktree without blocking inspection."""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

import worktree_cleanup


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LEASE_TTL = 30 * 60
READ_ONLY_PROGRAMS = {
    "cat", "file", "head", "ls", "pwd", "stat", "tail", "true", "wc", "which",
}
READ_ONLY_GIT = {
    "describe", "diff", "grep", "log", "ls-files", "merge-base", "name-rev", "rev-list", "rev-parse",
    "show", "status",
}
READ_ONLY_GIT_CONFIG = {"--get", "--get-all", "--get-regexp", "--list", "-l"}
READ_ONLY_GIT_BRANCH = {"--contains", "--list", "--points-at", "--show-current"}
KNOWN_GIT_SUBCOMMANDS = READ_ONLY_GIT | {
    "add", "am", "apply", "bisect", "branch", "checkout", "cherry-pick", "clean", "clone", "commit",
    "config", "fetch", "format-patch", "gc", "init", "merge", "mv", "notes", "pull", "push", "rebase",
    "remote", "reset", "restore", "revert", "rm", "send-pack", "sparse-checkout", "stash", "submodule",
    "switch", "tag", "worktree",
}
# Options carrying authored text rather than a further instruction. Their separate
# value is prose and must never be classified as an option of its own.
ISSUE_TEXT_OPTIONS = {"--body", "-b", "--body-file", "-F", "--title", "-t"}
ISSUE_BODY_OPTIONS = ISSUE_TEXT_OPTIONS - {"--title", "-t"}
# `create` keeps its historic option surface, limited only by the refusals in
# is_issue_bootstrap. `comment` and `edit` reach much further than the text, so
# they are reduced to the authoring options alone. Appending a comment is allowed;
# `--edit-last` is not, because it rewrites the newest comment of this account,
# which may be another worktree's claim marker.
ISSUE_AUTHORING_OPTIONS = {
    "create": None,
    "comment": ISSUE_BODY_OPTIONS,
    "edit": ISSUE_TEXT_OPTIONS,
}
# Options that hand control to another program or to a different repository.
ISSUE_REFUSED_OPTIONS = {"--editor", "--repo", "--web", "-R", "-e", "-w"}


def git(repository, *arguments, check=True):
    return subprocess.run(
        ("git", *arguments), cwd=repository, check=check, capture_output=True, text=True,
    )


def git_value(repository, *arguments):
    result = git(repository, *arguments, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def resolve_git_path(repository, value):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (repository / path).resolve()


def common_git_directory(repository):
    return resolve_git_path(repository, git_value(repository, "rev-parse", "--git-common-dir"))


def is_primary_worktree(repository):
    git_directory = resolve_git_path(repository, git_value(repository, "rev-parse", "--git-dir"))
    return git_directory == common_git_directory(repository)


def clean(repository):
    return not git_value(repository, "status", "--porcelain=v1", "--untracked-files=all")


def lease_directory(repository):
    return common_git_directory(repository) / "opnsense-agent-leases"


def lease_path(repository):
    key = hashlib.sha256(str(repository.resolve()).encode()).hexdigest()
    return lease_directory(repository) / f"{key}.json"


def read_lease(repository):
    try:
        return json.loads(lease_path(repository).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def write_lease(repository, value):
    directory = lease_directory(repository)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = lease_path(repository)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    temporary.replace(path)


def acquire_lease(repository, session_id, now=None):
    """Return an empty refusal when this session exclusively owns the worktree."""
    if not session_id:
        return "A writing agent needs a session identifier before it may own this worktree."

    now = time.time() if now is None else now
    current = read_lease(repository)
    if current.get("session_id") == session_id:
        current.pop("released_at", None)
        current["heartbeat_at"] = now
        write_lease(repository, current)
        worktree_cleanup.register(repository, session_id=session_id, now=now)
        return ""

    if current:
        heartbeat = float(current.get("heartbeat_at", current.get("acquired_at", 0)))
        released = bool(current.get("released_at"))
        if not clean(repository) or (not released and now - heartbeat <= LEASE_TTL):
            owner = str(current.get("session_id", "unknown"))[:12]
            return (
                f"This worktree is owned by another writing task ({owner}). Resume that task or use a separate "
                "worktree; a dirty worktree is never taken over automatically."
            )

    if not clean(repository):
        return (
            "This worktree already contains unowned changes. Resume the task that created them or hand them over "
            "deliberately before another agent writes here."
        )

    write_lease(repository, {
        "session_id": session_id,
        "worktree": str(repository.resolve()),
        "acquired_at": now,
        "heartbeat_at": now,
    })
    worktree_cleanup.register(repository, session_id=session_id, now=now)
    return ""


def release_lease(repository, session_id):
    current = read_lease(repository)
    if current.get("session_id") != session_id:
        return
    if not clean(repository):
        current["released_at"] = time.time()
        write_lease(repository, current)
        return
    try:
        lease_path(repository).unlink()
    except FileNotFoundError:
        pass


def leases(repository):
    directory = lease_directory(repository)
    if not directory.is_dir():
        return []
    records = []
    for path in sorted(directory.glob("*.json")):
        try:
            records.append(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return records


def event_command(event):
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return ""
    return str(tool_input.get("command") or tool_input.get("cmd") or "")


def _git_config(*arguments):
    result = subprocess.run(
        ("git", "config", *arguments), cwd=REPOSITORY_ROOT, check=False, capture_output=True, text=True,
    )
    return result.stdout.splitlines() if result.returncode == 0 else []


def _gh_config(key):
    result = subprocess.run(
        ("gh", "config", "get", key), cwd=REPOSITORY_ROOT, check=False, capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _configured_gh_pager():
    # GitHub CLI only starts a pager for terminal output, but the hook cannot
    # infer whether a supported client's shell tool owns a terminal. Reject an
    # explicitly selected program before it can turn inspection into a write.
    pager = next(
        (os.environ[name].strip() for name in ("GH_PAGER", "PAGER") if os.environ.get(name, "").strip()),
        "",
    ) or _gh_config("pager").strip()
    return pager.lower() not in ("", "cat")


def _configured_git_helper(command, arguments, global_arguments):
    if any(value == "-C" or value.startswith("-C") for value in global_arguments):
        # A different repository has different pager, fsmonitor and diff
        # configuration. The control-checkout allow-list never inspects it.
        return True
    if any(
        value in ("-c", "--config-env") or value.startswith("-c") and value != "-c"
        or value.startswith("--config-env=")
        for value in global_arguments
    ):
        return True
    disabled = {"", "0", "false", "no", "off"}
    fsmonitor = _git_config("--get-all", "core.fsmonitor")
    if any(value.strip().lower() not in disabled for value in fsmonitor):
        return True

    no_pager_index = max(
        (index for index, value in enumerate(global_arguments) if value in ("--no-pager", "-P")), default=-1,
    )
    pager_index = max(
        (index for index, value in enumerate(global_arguments) if value in ("--paginate", "-p")), default=-1,
    )
    if pager_index >= 0:
        return True
    no_pager = no_pager_index >= 0
    pagers = _git_config("--get-all", f"pager.{command}") or _git_config("--get-all", "core.pager")
    environment_pagers = [os.environ.get("GIT_PAGER", ""), os.environ.get("PAGER", "")]
    if not no_pager and any(value.strip().lower() not in disabled for value in environment_pagers):
        return True
    if not no_pager and any(value.strip().lower() not in disabled for value in pagers):
        return True

    if command in ("diff", "log", "show"):
        external = _git_config("--get-all", "diff.external")
        if (os.environ.get("GIT_EXTERNAL_DIFF") or external) and "--no-ext-diff" not in arguments:
            return True
        textconv = _git_config("--get-regexp", r"^diff\..*\.textconv$")
        if textconv and "--no-textconv" not in arguments:
            return True
    return False


def _read_only_git(arguments):
    if not arguments:
        return False
    command, rest, global_arguments = _git_invocation(arguments)
    if not command or _configured_git_helper(command, arguments, global_arguments):
        return False
    if command in READ_ONLY_GIT:
        executable = {"--ext-diff", "--textconv"}
        if command == "grep":
            executable.add("--open-files-in-pager")
            if any(argument == "-O" or argument.startswith("-O") for argument in rest):
                return False
        return not any(
            argument == "--output" or argument.startswith("--output=")
            or argument in executable or argument.startswith("--open-files-in-pager=")
            for argument in rest
        )
    if command == "branch":
        mutations = {
            "-c", "-C", "-d", "-D", "-m", "-M", "--copy", "--delete", "--edit-description", "--move",
            "-f", "--force", "--set-upstream-to", "--unset-upstream",
        }
        return bool(READ_ONLY_GIT_BRANCH & set(rest)) and not mutations.intersection(rest)
    if command == "config":
        mutations = {
            "--add", "--edit", "-e", "--remove-section", "--rename-section", "--replace-all", "--unset",
            "--unset-all",
        }
        return bool(READ_ONLY_GIT_CONFIG & set(rest)) and not mutations.intersection(rest)
    if command == "remote":
        if rest == ["-v"]:
            return True
        if rest and rest[0] == "get-url":
            return all(value in ("--all", "--push") or not value.startswith("-") for value in rest[1:])
        if rest and rest[0] == "show":
            return "-n" in rest[1:] and all(
                value == "-n" or not value.startswith("-") for value in rest[1:]
            )
        return False
    if command == "worktree":
        return bool(rest) and rest[0] == "list"
    return False


def _read_only_find(arguments):
    dangerous = {
        "-delete", "-exec", "-execdir", "-fls", "-fprint", "-fprint0", "-fprintf", "-ok", "-okdir",
    }
    return not any(argument.split("=", 1)[0] in dangerous for argument in arguments)


def _read_only_sed(arguments):
    values = list(arguments)
    while values and values[0] in ("-n", "--quiet", "--silent"):
        values.pop(0)
    if len(values) < 2 or any(value.startswith("-") for value in values[1:]):
        return False
    # sed can write through its command language (`w`) or execute a command
    # (`e`) without using --in-place. Only the small line-printing grammar used
    # for inspection is safe enough for the control checkout.
    return bool(re.fullmatch(r"(?:\d+(?:,\d+)?|\$)?[pq]", values[0]))


def _read_only_rg(arguments):
    executable_options = ("--hostname-bin", "--pre")
    option_end = arguments.index("--") if "--" in arguments else len(arguments)
    if os.environ.get("RIPGREP_CONFIG_PATH") and "--no-config" not in arguments[:option_end]:
        return False
    return not any(
        argument == option or argument.startswith(f"{option}=")
        for argument in arguments for option in executable_options
    )


def _repository_helper(arguments, relative_path, commands):
    if len(arguments) < 2:
        return False
    script = Path(arguments[0])
    resolved = script.resolve() if script.is_absolute() else (Path.cwd() / script).resolve()
    return resolved == (REPOSITORY_ROOT / relative_path).resolve() and arguments[1] in commands


def _worktree_helper(arguments):
    return _repository_helper(
        arguments, ".agents/worktrees.py", ("audit", "create", "list", "retire", "sweep"),
    )


def _hook_control(arguments):
    return _repository_helper(
        arguments, ".agents/hooks/fast_gate.py",
        ("acknowledge-main", "checkpoint-main", "defer-main", "refresh", "watch"),
    )


def _issue_helper(arguments):
    return _repository_helper(
        arguments, ".agents/issues.py", ("adopt-pr", "claim", "linked", "release"),
    )


def _review_wait_helper(arguments):
    return (
        _repository_helper(arguments, ".agents/review-requests.py", ("wait",))
        and len(arguments) == 4
        and arguments[1:3] == ["wait", "--phase"]
        and arguments[3] in ("review", "ready")
    )


def _read_only_gh(arguments):
    if any(value.split("=", 1)[0] in ("--web", "-w") for value in arguments):
        return False
    if _configured_gh_pager():
        return False
    if len(arguments) >= 2 and arguments[0] in ("issue", "pr", "repo", "run"):
        read_actions = {
            "issue": {"list", "status", "view"},
            "pr": {"checks", "diff", "list", "status", "view"},
            "repo": {"list", "view"},
            "run": {"list", "view", "watch"},
        }
        return arguments[1] in read_actions[arguments[0]]
    if arguments and arguments[0] == "search":
        return True
    if arguments and arguments[0] == "api":
        mutations = ("--field", "-f", "--input", "--raw-field", "-F")
        if any(
            value == option or value.startswith(f"{option}=")
            or (option in ("-f", "-F") and value.startswith(option) and value != option)
            for value in arguments[1:] for option in mutations
        ):
            return False
        for index, value in enumerate(arguments[1:]):
            if value in ("--method", "-X"):
                try:
                    return arguments[index + 2].upper() in ("GET", "HEAD")
                except IndexError:
                    return False
            if value.startswith("--method="):
                return value.partition("=")[2].upper() in ("GET", "HEAD")
            if value.startswith("-X") and value != "-X":
                return value[2:].upper() in ("GET", "HEAD")
        return True
    return False


def _shell_hazard(command):
    """Return control or expansion for unquoted syntax that changes literal arguments."""
    quote = ""
    escaped = False
    for value in command:
        if escaped:
            if value in "\r\n":
                return "control"
            escaped = False
            continue
        if value == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if value == quote:
                quote = ""
            elif quote == '"' and value in "$`":
                return "expansion"
            continue
        if value in "'\"":
            quote = value
        elif value in "\r\n;&|<>!()":
            return "control"
        elif value in "`$*?[]{}~":
            return "expansion"
    return ""


def _literal_shell_invocation(command):
    """Split one simple command while retaining expansion markers as literal evidence."""
    if not command.strip() or _shell_hazard(command) == "control":
        return "", []
    try:
        arguments = shlex.split(command)
    except ValueError:
        return "", []
    if not arguments:
        return "", []
    return arguments[0], arguments[1:]


def _shell_invocation(command):
    # The allow-list classifies the literal arguments below. Parameter expansion
    # would let the shell turn an apparently harmless literal into an executable
    # option only after that classification has completed.
    if _shell_hazard(command):
        return "", []
    try:
        arguments = shlex.split(command)
    except ValueError:
        return "", []
    if arguments and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", arguments[0]):
        return "", []
    if not arguments:
        return "", []

    program = arguments.pop(0)
    # A basename match is not an executable identity: /tmp/git is unrelated to
    # the trusted git found through the task's controlled PATH.
    if Path(program).name != program:
        return "", []
    if program == "env":
        return "", []
    return program, arguments


def is_read_only_shell(command):
    """Accept a deliberately small grammar; ambiguity belongs in an isolated worktree."""
    literal_program, literal_arguments = _literal_shell_invocation(command)
    if not _shell_hazard(command) and _review_wait_helper([literal_program, *literal_arguments]):
        return True
    if (literal_program == "GIT_OPTIONAL_LOCKS=0" and literal_arguments
            and literal_arguments[0] == "git" and not _shell_hazard(command)):
        return _read_only_git(literal_arguments[1:])
    program, arguments = _shell_invocation(command)
    if not program:
        return False
    if program in READ_ONLY_PROGRAMS:
        return True
    if program == "find":
        return _read_only_find(arguments)
    if program == "sed":
        return _read_only_sed(arguments)
    if program == "rg":
        return _read_only_rg(arguments)
    if program == "git":
        # Even inspection may refresh the index. The exact environment prefix
        # above is part of the read-only contract for the control checkout.
        return False
    if program == "gh":
        return _read_only_gh(arguments)
    if program in ("python", "python3"):
        return (
            _worktree_helper(arguments) or _hook_control(arguments) or _issue_helper(arguments)
            or _review_wait_helper(arguments)
        )
    return False


def _issue_options(arguments):
    """Return the real options of one issue command, skipping the authored text values.

    A separate value belongs to the option before it, and authored prose may legitimately
    begin with a dash. Classifying it as an option would refuse a body that merely quotes
    one, so the text-carrying options consume their value here.
    """
    options = []
    index = 0
    while index < len(arguments):
        value = arguments[index]
        if not value.startswith("-") or value == "-":
            index += 1
            continue
        name = value.split("=", 1)[0]
        short_value = len(name) > 2 and not name.startswith("--") and name[:2] in ISSUE_TEXT_OPTIONS
        option = name[:2] if short_value else name
        options.append(option)
        joined = short_value or "=" in value
        index += 2 if option in ISSUE_TEXT_OPTIONS and not joined else 1
    return options


def is_issue_bootstrap(event):
    """Allow one public issue to be created and completed before repository writes begin.

    Opening the issue is how a task starts, and the contribution rules then require its
    maintained detail comment and, when the body was wrong, a correction of that body.
    None of that is implementation, so demanding a work claim first would force an agent
    to announce implementation that is not starting. What stays outside are the operations
    that can move another task's claim: its labels, and rewriting an existing comment.
    """
    if str(event.get("tool_name") or "") != "Bash":
        return False
    program, arguments = _shell_invocation(event_command(event))
    if program != "gh" or len(arguments) < 2 or arguments[0] != "issue":
        return False
    action = arguments[1]
    if action not in ISSUE_AUTHORING_OPTIONS:
        return False
    options = _issue_options(arguments[2:])
    if any(option in ISSUE_REFUSED_OPTIONS or option.startswith("-R") for option in options):
        return False
    allowed = ISSUE_AUTHORING_OPTIONS[action]
    if allowed is None:
        return True
    # Without authored text both commands would open the configured editor, which
    # is the same handover to another program the refusals above prevent.
    return all(option in allowed for option in options) and any(
        option in ISSUE_TEXT_OPTIONS for option in options
    )


def is_main_acknowledgement(event):
    """Recognize only the repository-owned helper that records a drift decision."""
    if str(event.get("tool_name") or "") != "Bash":
        return False
    program, arguments = _shell_invocation(event_command(event))
    return bool(
        program in ("python", "python3")
        and _repository_helper(arguments, ".agents/hooks/fast_gate.py", ("acknowledge-main",))
        and arguments[1] == "acknowledge-main"
    )


def is_continuity_control(event):
    """Recognize only the repository-owned helper that starts or ends one protected phase."""
    if str(event.get("tool_name") or "") != "Bash":
        return False
    program, arguments = _shell_invocation(event_command(event))
    return bool(
        program in ("python", "python3")
        and _repository_helper(arguments, ".agents/hooks/fast_gate.py", ("checkpoint-main", "defer-main"))
        and arguments[1] in ("checkpoint-main", "defer-main")
    )


def pull_reconciliation_sha(event):
    """Return the exact foreign PR head named by the repository-owned reconciliation helper."""
    if str(event.get("tool_name") or "") != "Bash":
        return ""
    program, arguments = _shell_invocation(event_command(event))
    if not (
        program in ("python", "python3")
        and _repository_helper(arguments, ".agents/hooks/fast_gate.py", ("reconcile-pr",))
        and len(arguments) == 6
        and arguments[1:3] == ["reconcile-pr", "--sha"]
        and arguments[4:] == ["--strategy", "merge"]
    ):
        return ""
    return arguments[3] if re.fullmatch(r"[0-9a-f]{40}", arguments[3]) else ""


def _git_invocation(arguments):
    """Locate a Git subcommand behind the documented global option grammar."""
    index = 0
    with_value = {"-C", "-c", "--config-env", "--git-dir", "--namespace", "--work-tree"}
    flags = {
        "--bare", "--glob-pathspecs", "--help", "--html-path", "--icase-pathspecs", "--info-path",
        "--literal-pathspecs", "--man-path", "--no-advice", "--no-lazy-fetch", "--no-optional-locks",
        "--no-pager", "--no-replace-objects", "--noglob-pathspecs", "--paginate", "--version", "-P", "-p",
    }
    equals = {"--config-env", "--exec-path", "--git-dir", "--namespace", "--work-tree"}
    while index < len(arguments):
        value = arguments[index]
        if value == "--":
            index += 1
            break
        if value in with_value:
            index += 2
            if index > len(arguments):
                return "", [], []
            continue
        if value in flags or any(value.startswith(f"{option}=") for option in equals):
            index += 1
            continue
        if ((value.startswith("-C") or value.startswith("-c")) and len(value) > 2):
            index += 1
            continue
        if value.startswith("-"):
            return "", [], []
        return value, arguments[index + 1:], arguments[:index]
    if index < len(arguments):
        return arguments[index], arguments[index + 1:], arguments[:index]
    return "", [], []


def _git_subcommand(arguments):
    command, rest, _global_arguments = _git_invocation(arguments)
    return command, rest


def _effective_invocation(command):
    """Unwrap simple execution builtins without trying to interpret a shell program."""
    if _shell_hazard(command) == "control":
        return "", [], True
    program, arguments = _literal_shell_invocation(command)
    while re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", program):
        if not arguments:
            return program, arguments, True
        program, arguments = arguments[0], arguments[1:]
    for _depth in range(4):
        if program == "builtin" and arguments and arguments[0] in ("command", "exec"):
            program, arguments = arguments[0], arguments[1:]
            continue
        if program == "command":
            while arguments and arguments[0] in ("--", "-p"):
                arguments.pop(0)
            if not arguments or arguments[0] in ("-V", "-v"):
                return program, arguments, True
            program, arguments = arguments[0], arguments[1:]
            continue
        if program == "exec":
            while arguments and arguments[0] in ("--", "-c", "-l"):
                arguments.pop(0)
            if arguments and arguments[0] == "-a":
                if len(arguments) < 3:
                    return program, arguments, True
                arguments = arguments[2:]
            if not arguments:
                return program, arguments, True
            program, arguments = arguments[0], arguments[1:]
            continue
        if program == "env":
            while arguments:
                value = arguments[0]
                if value == "--":
                    arguments.pop(0)
                    break
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", value):
                    arguments.pop(0)
                    continue
                if value in ("-i", "--ignore-environment") or value.startswith("--unset="):
                    arguments.pop(0)
                    continue
                if value in ("-C", "--chdir", "-u", "--unset"):
                    if len(arguments) < 2:
                        return program, arguments, True
                    arguments = arguments[2:]
                    continue
                if value.startswith("-"):
                    return program, arguments, True
                break
            if not arguments:
                return program, arguments, True
            program, arguments = arguments[0], arguments[1:]
            continue
        interpreter_options = {
            "bash": "c", "dash": "c", "ksh": "c", "sh": "c", "zsh": "c",
            "node": "e", "perl": "e", "php": "r", "python": "c", "python3": "c", "ruby": "e",
        }
        name = Path(program).name
        option = interpreter_options.get(name)
        if (program in (
                ".", "chrt", "coproc", "daemon", "doas", "eval", "flock", "ionice", "nice", "nohup", "parallel",
                "script", "setsid", "source", "stdbuf", "sudo", "time", "timeout", "unbuffer", "watch", "xargs",
        )
                or (option and any(value.startswith("-") and option in value[1:] for value in arguments))):
            return program, arguments, True
        break
    return program, arguments, program in ("builtin", "command", "env", "exec")


def _coordination_publication(program, arguments):
    return (
        Path(program).name == "pr-coordination.py"
        and any(command in ("recommend", "fulfill") for command in arguments)
    ) or any(
        Path(value).name == "pr-coordination.py"
        and any(command in ("recommend", "fulfill") for command in arguments[index + 1:])
        for index, value in enumerate(arguments)
    )


def _review_request_publication(program, arguments):
    return (
        Path(program).name == "review-requests.py"
        and any(command in ("request", "cleanup") for command in arguments)
    ) or any(
        Path(value).name == "review-requests.py"
        and any(command in ("request", "cleanup") for command in arguments[index + 1:])
        for index, value in enumerate(arguments)
    )


def requires_uncached_remote(event):
    """Identify publication boundaries whose remote view must never come from the active-work cache."""
    tool = str(event.get("tool_name") or "")
    if tool.lower() == "handoff":
        return True
    if tool != "Bash":
        return False
    command = event_command(event)
    program, arguments, uncertain = _effective_invocation(command)
    if uncertain:
        return True
    if Path(program).name in ("git", "gh") and Path(program).name != program:
        return True
    if _shell_hazard(command) == "expansion" and (program == "git" or program == "gh" or not program.isidentifier()):
        return True
    git_command, _git_arguments = _git_subcommand(arguments) if program == "git" else ("", [])
    return bool(
        (program == "git" and git_command in ("push", "send-pack"))
        or (program == "git" and git_command not in KNOWN_GIT_SUBCOMMANDS)
        or (program == "gh" and not _read_only_gh(arguments))
        or _coordination_publication(program, arguments)
        or _review_request_publication(program, arguments)
        or (program not in ("git", "gh") and any(Path(value).name in ("git", "gh") for value in arguments))
    )


def requires_topic_branch(event):
    """Keep a managed detached worktree valid until it creates durable Git or GitHub state."""
    if str(event.get("tool_name") or "") != "Bash":
        return False
    command = event_command(event)
    program, arguments, uncertain = _effective_invocation(command)
    if uncertain:
        return True
    if Path(program).name in ("git", "gh") and Path(program).name != program:
        return True
    if _shell_hazard(command) == "expansion" and (program == "git" or program == "gh" or not program.isidentifier()):
        return True
    git_command, _git_arguments = _git_subcommand(arguments) if program == "git" else ("", [])
    nested_durable = False
    if program not in ("git", "gh"):
        for index, value in enumerate(arguments):
            nested_program = Path(value).name
            if nested_program == "git":
                nested_command, _nested_arguments = _git_subcommand(arguments[index + 1:])
                nested_durable = nested_command in ("commit", "push", "send-pack")
            elif nested_program == "gh":
                nested_durable = not _read_only_gh(arguments[index + 1:])
            if nested_durable:
                break
    return bool(
        (program == "git" and git_command in ("commit", "push", "send-pack"))
        or (program == "git" and git_command not in KNOWN_GIT_SUBCOMMANDS)
        or (program == "gh" and not _read_only_gh(arguments))
        or _coordination_publication(program, arguments)
        or _review_request_publication(program, arguments)
        or nested_durable
    )


def is_read_only_agent(event):
    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        return False
    message = str(tool_input.get("message") or tool_input.get("prompt") or "")
    return "[read-only]" in message.lower()


def tool_requires_write(event):
    tool = str(event.get("tool_name") or "")
    if tool == "Bash":
        return not is_read_only_shell(event_command(event))
    return tool in ("apply_patch", "Edit", "Write", "Handoff")


def blocked(reason):
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
