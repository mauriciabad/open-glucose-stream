# Open Glucose Stream reference — https://github.com/mauriciabad/open-glucose-stream
# SPDX-FileCopyrightText: 2026 Maurici Abad
# SPDX-License-Identifier: CC0-1.0
"""ogs — Open Glucose Stream reference tool.

  ogs d3 vectors generate|verify [FILE]   draft 3 test vectors (test-vectors/ogs-draft3.json)
  ogs d3 e2e [--relays URL,...]           draft 3 end to end on public relays: owner, two members, a writer, removal
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[2] / "test-vectors" / "ogs-draft3.json"


def cmd_d3(a) -> int:
    from .d3 import vectors as v3
    if a.what == "e2e":
        from .d3.e2e import run
        return asyncio.run(run([u for u in a.relays.split(",") if u]))
    path = Path(a.file or VECTORS)
    if a.action == "generate":
        vec = v3.generate()
        v3.verify_file(vec, fill_final=True)
        path.write_text(v3.dumps(vec))
        print(f"wrote {path}")
    vec = json.loads(path.read_text())
    fails = v3.verify_file(vec)
    for f in fails:
        print("FAIL", f)
    print(f"{'FAIL' if fails else 'PASS'}: {len(vec['events'])} events, {len(vec['plaintexts'])} wraps opened, "
          f"{len(vec['tree']['covers'])} covers, {len(vec['invite_checks'])} invite checks, "
          f"{len(vec['owner_checks'])} owner checks, BLE at {len(vec['ble']['frames_by_att_mtu'])} MTUs, "
          f"scenario {len(vec['scenario']['steps'])} steps")
    return 1 if fails else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ogs", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    d3 = sub.add_parser("d3")
    d3s = d3.add_subparsers(dest="what", required=True)
    d3v = d3s.add_parser("vectors")
    d3v.add_argument("action", choices=["generate", "verify"])
    d3v.add_argument("file", nargs="?")
    d3e = d3s.add_parser("e2e")
    d3e.add_argument("--relays", default="wss://nos.lol,wss://relay.primal.net,wss://nostr.mom")
    a = p.parse_args(argv)
    return cmd_d3(a)


if __name__ == "__main__":
    sys.exit(main())
