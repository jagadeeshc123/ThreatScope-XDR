import argparse
import json

from app.modules.platform_operations.release_service import build_release


def main(argv=None):
    parser=argparse.ArgumentParser(description="Build a bounded local ThreatScope release candidate")
    parser.add_argument("--allow-dirty",action="store_true",help="Explicitly build a candidate marked dirty")
    args=parser.parse_args(argv)
    try: result,path=build_release(allow_dirty=args.allow_dirty)
    except ValueError as exc: parser.error(str(exc))
    print(json.dumps({"artifact":path.name,"sha256":result["sha256"],"dirty":result["dirty_working_tree"]},sort_keys=True));return 0


if __name__=="__main__": raise SystemExit(main())
