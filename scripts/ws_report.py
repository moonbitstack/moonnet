#!/usr/bin/env python3
# Read the verdict Autobahn's fuzzing server wrote and say whether every case passed. The
# server's report is the authority here: the client never grades itself.
import json
import sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "index.json"
agent = sys.argv[2] if len(sys.argv) > 2 else "moonnet"

report = json.load(open(path, encoding="utf-8"))[agent]
counts = Counter(case["behavior"] for case in report.values())
total = len(report)
# The suite grades a case three ways: OK, NON-STRICT (it worked, but not in the way the case
# prefers), INFORMATIONAL (nothing to grade), and FAILED.
failed = sorted(
    case for case, v in report.items() if v["behavior"] == "FAILED"
)
graded = counts.get("OK", 0) + counts.get("NON-STRICT", 0)

print(f"WebSocket conformance · {agent}")
print(f"  cases        {total}")
for behavior in ["OK", "NON-STRICT", "INFORMATIONAL", "FAILED"]:
    if counts.get(behavior):
        print(f"  {behavior:<12} {counts[behavior]}")
print(f"  passed       {graded}/{graded + len(failed)}")
if failed:
    print("  failed       " + " ".join(failed[:40]))
sys.exit(0 if not failed else 1)
