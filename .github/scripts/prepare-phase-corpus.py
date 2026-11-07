"""Copy exact, hash-checked test inputs without modifying the source hoard.

This prepares CI data only; it executes no firmware conversion or test matrix.
Recovered historical components may be supplied in a separate directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def prepare(manifest, hoard, output, recovered=None):
    inventory = json.loads(manifest.read_text())
    required = set()
    for domain in inventory["domains"]:
        for record in domain["records"]:
            required.add(record["normal"])
            if record["kernel"]:
                required.add(record["kernel"])
    output.mkdir(parents=True, exist_ok=True)
    found = {}

    def retain(expected, data, source):
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ValueError(f"{source}: expected {expected}, received {actual}")
        destination = output / f"{expected}.enc"
        if destination.exists() and destination.read_bytes() != data:
            raise ValueError(f"refusing to replace mismatching {destination}")
        destination.write_bytes(data)
        found[expected] = {"bytes": len(data), "source": str(source)}

    packages = json.loads((hoard / "index/packages.json").read_text())["packages"]
    for package in packages:
        wanted = [c for c in package["components"]
                  if c["sha256"] in required and c["sha256"] not in found]
        if not wanted:
            continue
        path = hoard / package["path"]
        if not path.is_file():
            continue
        with tarfile.open(path) as archive:
            for component in wanted:
                member = archive.getmember(component["member"])
                if not member.isfile() or member.size > 64 * 1024 * 1024:
                    raise ValueError(f"invalid component member: {path}:{member.name}")
                with archive.extractfile(member) as stream:
                    retain(component["sha256"], stream.read(), f"{path}:{member.name}")
    if recovered:
        for expected in sorted(required - found.keys()):
            path = recovered / f"{expected}.enc"
            if path.is_file():
                retain(expected, path.read_bytes(), path)
    missing = sorted(required - found.keys())
    receipt = {
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "required_components": len(required),
        "found": found,
        "missing": missing,
    }
    (output / "input-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if missing:
        raise ValueError(f"missing {len(missing)} required components: {missing}")
    print(f"Prepared {len(found)} exact components; source hoard unchanged.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--hoard", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--recovered", type=Path)
    args = parser.parse_args()
    prepare(args.manifest, args.hoard, args.output, args.recovered)
