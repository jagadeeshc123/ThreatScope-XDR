import argparse
import json

from app import models  # noqa: F401
from app.database import SessionLocal
from app.modules.platform_operations import demo_service


def main(argv=None):
    parser=argparse.ArgumentParser(description="Manage deterministic synthetic local demo records")
    parser.add_argument("mode",choices=["seed","status","reset","reseed"])
    parser.add_argument("--confirm",default="")
    args=parser.parse_args(argv)
    with SessionLocal() as db:
        if args.mode=="status": result=demo_service.status(db)
        elif args.mode=="seed": result=demo_service.seed(db)
        elif args.mode=="reset":
            if args.confirm!="RESET DEMO DATA":parser.error("--confirm 'RESET DEMO DATA' is required")
            result=demo_service.reset(db)
        else:
            if args.confirm!="RESEED DEMO DATA":parser.error("--confirm 'RESEED DEMO DATA' is required")
            demo_service.reset(db);result=demo_service.seed(db)
    print(json.dumps(result,sort_keys=True,default=str));return 0


if __name__=="__main__": raise SystemExit(main())
