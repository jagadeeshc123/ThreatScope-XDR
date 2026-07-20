import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.modules.production.preflight import run_preflight  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the safe ThreatScope production startup preflight.")
    parser.add_argument("--json", action="store_true", help="Emit bounded JSON output.")
    parser.add_argument("--create-directories", action="store_true", help="Create configured writable runtime directories.")
    args = parser.parse_args()
    result = run_preflight(create_directories=args.create_directories)
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(f"Production preflight: {result['status']} ({result['failure_count']} failures, {result['warning_count']} warnings)")
        for check in result["checks"]:
            print(f"[{check['state'].upper()}] {check['name']}: {check['summary']} ({check['remediation_code']})")
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
