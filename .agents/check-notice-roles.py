#!/usr/bin/env python3

"""Check that first-party copyright notices appear only in their allowed roles."""

from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def project_notice(root):
    for line in (root / "LICENSE").read_text(encoding="utf-8").splitlines():
        if line.startswith("Copyright"):
            holder = line.split(",", 1)[1].strip() if "," in line else line
            year = re.search(r"\b(\d{4})\b", line)
            return f"Copyright (C) {year.group(1)} {holder}" if year else None
    return None


def notice_role_mismatches(root, tracked_names):
    notice = project_notice(root)
    if notice is None:
        raise ValueError("LICENSE carries no copyright holder for the application headers")

    tracked = {root / name for name in tracked_names if (root / name).is_file()}
    expected = {root / "LICENSE", root / "packaging/watch/openid-connect-refresh"}
    expected.update(
        path for path in tracked
        if path.is_relative_to(root / "src/opnsense") and path.suffix in {".php", ".js", ".css"}
    )
    actual = {root / "LICENSE"}
    actual.update({
        path for path in tracked
        if notice in path.read_text(encoding="utf-8", errors="replace")
    })
    return (
        sorted(str(path.relative_to(root)) for path in actual - expected),
        sorted(str(path.relative_to(root)) for path in expected - actual),
    )


def main():
    tracked = subprocess.run(
        ("git", "-C", str(ROOT), "ls-files", "-z"), capture_output=True, check=True,
    ).stdout.decode().split("\0")
    extra, missing = notice_role_mismatches(ROOT, tracked)
    if extra or missing:
        if extra:
            print(f"copyright notice is not allowed in: {', '.join(extra)}", file=sys.stderr)
        if missing:
            print(f"copyright notice is missing from: {', '.join(missing)}", file=sys.stderr)
        return 1
    print("repository notice roles are consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
