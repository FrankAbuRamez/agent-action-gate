"""Usage:
    python -m gate check intent.json        evaluate a proposed action
    python -m gate verify-log               check the audit log for tampering
    python -m gate kill on|off              block or unblock all agent actions
"""
import argparse
import json
from pathlib import Path

from .core import load_gate, verify_log


def main() -> None:
    parser = argparse.ArgumentParser(prog="gate")
    parser.add_argument("--policy", default="policy.example.json")
    parser.add_argument("--log", default="audit.log.jsonl")
    parser.add_argument("--kill-switch", default="KILL_SWITCH")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check")
    check.add_argument("intent")
    sub.add_parser("verify-log")
    kill = sub.add_parser("kill")
    kill.add_argument("state", choices=["on", "off"])
    args = parser.parse_args()

    if args.cmd == "check":
        gate = load_gate(args.policy, args.log, args.kill_switch)
        decision = gate.evaluate(json.loads(Path(args.intent).read_text(encoding="utf-8")))
        print(json.dumps(decision.__dict__, indent=2))
    elif args.cmd == "verify-log":
        ok, message = verify_log(Path(args.log))
        print(("OK: " if ok else "TAMPERED: ") + message)
        raise SystemExit(0 if ok else 1)
    elif args.cmd == "kill":
        path = Path(args.kill_switch)
        if args.state == "on":
            path.write_text("agent actions blocked\n", encoding="utf-8")
        elif path.exists():
            path.unlink()
        print(f"kill switch {args.state}")


if __name__ == "__main__":
    main()
