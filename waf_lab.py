#!/usr/bin/env python3
"""JSON-only entry point for the guarded conversational WAF lab tools."""

import argparse
import asyncio
import json
import signal
import sys

from modules.lab_catalogue import catalogue
from modules.lab_runner import LabRunner, report_view, review_view


async def dispatch(args, payload=None):
    runner = LabRunner()
    if args.command == "catalog":
        return catalogue()
    if args.command == "inventory":
        if set(payload) != {"targets"} or not isinstance(payload["targets"], list):
            raise ValueError("Inventory input requires only a targets array")
        return await runner.inventory(payload["targets"])
    if args.command == "plan":
        return await runner.plan(payload)
    if args.command == "show":
        return runner.read(args.plan_id, "plan.json")
    if args.command == "review":
        return review_view(runner.read(args.plan_id, "plan.json"), args.offset, args.limit)
    if args.command == "run":
        return report_view(await runner.run(args.plan_id, args.approve))
    if args.command == "report":
        return report_view(runner.read(args.plan_id, "report.json"), args.section, args.offset, args.limit)
    if args.command == "correlate":
        return report_view(await runner.correlate(args.plan_id))
    return runner.compare(args.plan_id, args.baseline_id)


async def cancellable_dispatch(args, payload):
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, task.cancel)
        except (NotImplementedError, RuntimeError):
            pass
    return await dispatch(args, payload)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("catalog")
    for name in ("inventory", "plan"):
        command = commands.add_parser(name)
        command.add_argument("--input", choices=["-"], required=True, help="JSON object on stdin")
    for name in ("show", "review", "run", "report", "correlate", "compare"):
        command = commands.add_parser(name)
        command.add_argument("--plan-id", required=True)
        if name == "run":
            command.add_argument("--approve", required=True, help="Exact digest of the reviewed plan")
        elif name == "compare":
            command.add_argument("--baseline-id", required=True)
        elif name == "report":
            command.add_argument("--section", choices=["summary", "attempts", "rules", "plan", "inventory"], default="summary")
            command.add_argument("--offset", type=int, default=0)
            command.add_argument("--limit", type=int, default=20)
        elif name == "review":
            command.add_argument("--offset", type=int, default=0)
            command.add_argument("--limit", type=int, default=5)
    args = parser.parse_args(argv)
    try:
        payload = None
        if args.command in ("inventory", "plan"):
            raw = sys.stdin.read(65537)
            if len(raw) > 65536:
                raise ValueError("Input exceeds 64 KiB")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("Input must be a JSON object")
        result = asyncio.run(cancellable_dispatch(args, payload))
        json.dump(result, sys.stdout, allow_nan=False)
        sys.stdout.write("\n")
        return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # State/API bodies and credentials are never interpolated into diagnostics.
        message = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else type(exc).__name__
        json.dump({"error": message}, sys.stdout)
        sys.stdout.write("\n")
        return 1
    except (KeyboardInterrupt, asyncio.CancelledError):
        json.dump({"error": "Operation cancelled"}, sys.stdout)
        sys.stdout.write("\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
