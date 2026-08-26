#!/usr/bin/env python3

"""Publish one complete documentation screenshot generation."""

import argparse
import fcntl
import hashlib
import os
import pathlib
import shutil
import signal
import stat
import tempfile


SCREENSHOTS = (
    "login-and-recovery.png",
    "connection-health.png",
    "test-sign-in.png",
    "bound-identities.png",
    "pending-approvals.png",
)


def lock_path(output):
    lock_root = pathlib.Path(tempfile.gettempdir()) / f"opnsense-oidc-screenshot-locks-{os.getuid()}"
    lock_root.mkdir(mode=0o700, exist_ok=True)
    details = lock_root.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise RuntimeError(f"unsafe screenshot lock directory: {lock_root}")
    identity = hashlib.sha256(str(output.resolve()).encode("utf-8")).hexdigest()
    return lock_root / f"{identity}.lock"


def remove(path):
    path.unlink(missing_ok=True)


def publish_screenshots(source, output, replace=os.replace, remove_path=remove, commit_marker=None):
    source = pathlib.Path(source)
    output = pathlib.Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name in SCREENSHOTS:
        candidate = source / name
        if not candidate.is_file() or candidate.stat().st_size == 0:
            raise RuntimeError(f"missing staged screenshot: {candidate}")

    lock = lock_path(output)
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
    temporary = {}
    backups = {}
    published = set()
    handled_signals = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
    previous_mask = None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            for name in SCREENSHOTS:
                with tempfile.NamedTemporaryFile(
                    dir=output, prefix=f".{name}.", suffix=".tmp", delete=False
                ) as staged:
                    temporary[name] = pathlib.Path(staged.name)
                    with (source / name).open("rb") as incoming:
                        shutil.copyfileobj(incoming, staged)
                    staged.flush()
                    os.fchmod(staged.fileno(), 0o644)
                    os.fsync(staged.fileno())

            generation = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
            for name in SCREENSHOTS:
                target = output / name
                if target.exists():
                    backup = output / f".{name}.{generation}.backup"
                    backups[name] = backup
                    replace(target, backup)
            for name in SCREENSHOTS:
                published.add(name)
                replace(temporary[name], output / name)
            # A signal before this atomic mask change still enters the rollback
            # handler with every backup available. Once masked, the complete new
            # generation is the commit and only its obsolete backups remain.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
        except BaseException as error:
            rollback_mask = signal.pthread_sigmask(signal.SIG_BLOCK, handled_signals)
            rollback_errors = []
            try:
                for name in published:
                    try:
                        remove_path(output / name)
                    except OSError as rollback_error:
                        rollback_errors.append(rollback_error)
                for name, backup in backups.items():
                    if not backup.exists():
                        continue
                    try:
                        replace(backup, output / name)
                    except OSError as rollback_error:
                        rollback_errors.append(rollback_error)
            finally:
                previous_handlers = {
                    handled_signal: signal.signal(handled_signal, signal.SIG_IGN)
                    for handled_signal in handled_signals
                }
                signal.pthread_sigmask(signal.SIG_SETMASK, rollback_mask)
                for handled_signal, previous_handler in previous_handlers.items():
                    signal.signal(handled_signal, previous_handler)
            if rollback_errors:
                raise RuntimeError("screenshot publication and rollback both failed") from error
            raise
        else:
            for backup in backups.values():
                try:
                    remove_path(backup)
                except OSError:
                    pass
            if commit_marker is not None:
                try:
                    pathlib.Path(commit_marker).write_text("committed\n", encoding="utf-8")
                except OSError:
                    pass
            previous_handlers = {
                handled_signal: signal.signal(handled_signal, signal.SIG_IGN)
                for handled_signal in handled_signals
            }
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            previous_mask = None
            for handled_signal, previous_handler in previous_handlers.items():
                signal.signal(handled_signal, previous_handler)
        finally:
            if previous_mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            for path in temporary.values():
                remove_path(path)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def interrupted(signum, _frame):
    raise InterruptedError(f"screenshot publication interrupted by signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--commit-marker", type=pathlib.Path)
    arguments = parser.parse_args()
    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled_signal, interrupted)
    publish_screenshots(arguments.source, arguments.output, commit_marker=arguments.commit_marker)


if __name__ == "__main__":
    main()
