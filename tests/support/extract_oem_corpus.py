#!/usr/bin/env python3
"""Extract only the pinned OEM envelopes. Never changes the source hoard."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("packages", type=Path, help="hoard/packages/pioneer directory")
parser.add_argument("output", type=Path, help="destination for hash-named .enc files")
args = parser.parse_args()
rows = json.loads(Path(__file__).with_name("oem_kernel_files.json").read_text())
args.output.mkdir(parents=True, exist_ok=True)
for row in rows:
    source = row["sources"][0]
    relative = source["package"]
    package = args.packages / relative
    package_hash = package.name.split(".", 1)[0]
    assert hashlib.sha256(package.read_bytes()).hexdigest() == package_hash, package
    with tarfile.open(package) as archive:
        data = archive.extractfile(source["member"]).read()
    assert hashlib.sha256(data).hexdigest() == row["envelope_sha256"], source
    (args.output / (row["envelope_sha256"] + ".enc")).write_bytes(data)
assert len({row["body_sha256"] for row in rows}) == 228
assert len(rows) == 290
print(f"Extracted and hash-verified {len(rows)} OEM envelopes to {args.output}")
