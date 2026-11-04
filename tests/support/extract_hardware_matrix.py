#!/usr/bin/env python3
"""Regenerate tests/fixtures/hardware-matrix.json from the owner's matrix HTML.

Usage: python3 -I tests/support/extract_hardware_matrix.py Pioneer-Hardware-Matrix.html \
           tests/fixtures/hardware-matrix.json

Only machine-readable data embedded in the HTML is copied; nothing is derived
from firmware. The HTML's SHA-256 is recorded so a stale fixture is visible.
"""
import hashlib
import json
import re
import sys


def block(html, name):
    m = re.search(r'<script id="%s" type="application/json">' % re.escape(name), html)
    if not m:
        raise SystemExit("missing data block " + name)
    return json.loads(html[m.end():html.index("</script>", m.end())])


def main(source, output):
    raw = open(source, "rb").read()
    html = raw.decode("utf-8")
    report = block(html, "report-data")
    registered = block(html, "registered-filter-data")
    layout = block(html, "all-platform-layout-data")
    rows = sorted(
        (
            {
                "component": r["component"],
                "hardware": r["hardware"],
                "as_is": r["as_is"],
                "candidate": r["candidate"],
            }
            for r in registered["rows"]
        ),
        key=lambda r: r["component"],
    )
    startup = {
        component: value.get("display")
        for component, value in sorted(report["startup009f"].items())
    }
    fixture = {
        "source": {"file": "Pioneer-Hardware-Matrix.html", "sha256": hashlib.sha256(raw).hexdigest()},
        "scheme": registered["scheme"],
        "owner_ids": sorted(registered["owner_ids"]),
        "counts": {"images": registered["images"], "known": registered["known"], "unresolved": registered["unresolved"]},
        "candidate_splits": registered["candidate_splits"],
        "rows": rows,
        "startup_009f": startup,
        "sat1_kernel_getter_needed": sorted(
            e["component"] for e in report["sat1StartupProofProgress"]["exact_kernel_getter_needed"]
        ),
        "layout": {"required": layout["required"], "correctable": layout["correctable"]},
        "phase_correction_policy": report["phaseCorrectionPolicy"],
        "phase_assignment_limits": report["normalPhaseAssignmentAudit"]["limits"],
        "bank_conversion_status": report["bankAndPhaseConversion"]["filters"]["bank"]["status"],
        "platform_policy": report["platformPolicy"],
        "compatibility_kats": report["compatibilityKats"],
    }
    with open(output, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
