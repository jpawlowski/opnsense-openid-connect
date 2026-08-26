#!/usr/bin/env python3

# Copyright (C) 2026 Julian Pawlowski
# All rights reserved. BSD-2-Clause, see LICENSE at the repository root.

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


def publish_screenshots(source, output, replace=os.replace):
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
        except BaseException as error:
            previous_handlers = {}
            for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                previous_handlers[handled_signal] = signal.signal(handled_signal, signal.SIG_IGN)
            rollback_errors = []
            try:
                for name in published:
                    try:
                        (output / name).unlink(missing_ok=True)
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
                for handled_signal, previous_handler in previous_handlers.items():
                    signal.signal(handled_signal, previous_handler)
            if rollback_errors:
                raise RuntimeError("screenshot publication and rollback both failed") from error
            raise
        else:
            for backup in backups.values():
                try:
                    backup.unlink(missing_ok=True)
                except OSError:
                    pass
        finally:
            for path in temporary.values():
                path.unlink(missing_ok=True)
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def interrupted(signum, _frame):
    raise InterruptedError(f"screenshot publication interrupted by signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    arguments = parser.parse_args()
    for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(handled_signal, interrupted)
    publish_screenshots(arguments.source, arguments.output)


if __name__ == "__main__":
    main()
