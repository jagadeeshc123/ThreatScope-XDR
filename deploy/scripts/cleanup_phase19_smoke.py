from __future__ import annotations

import shutil
from pathlib import Path


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    target = (repository / ".runtime" / "phase20-smoke").resolve()
    allowed_parent = (repository / ".runtime").resolve()
    if target.parent != allowed_parent or target.name != "phase20-smoke":
        raise SystemExit("Refusing to remove an unexpected path")
    if target.exists():
        shutil.rmtree(target)
    print("Phase 20 smoke material removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
