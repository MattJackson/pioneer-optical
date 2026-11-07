"""Fetch the pinned unpublished corpus using the job's temporary GitHub token."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile


def fetch(config, manifest, domain, output, conditional_manifest=None):
    pin = json.loads(config.read_text())
    raw_manifest = manifest.read_bytes()
    if hashlib.sha256(raw_manifest).hexdigest() != pin["inventory_sha256"]:
        raise ValueError("phase inventory changed without a matching corpus pin")
    raw_conditional = conditional_manifest.read_bytes() if conditional_manifest else None
    if (raw_conditional is not None and
            hashlib.sha256(raw_conditional).hexdigest() != pin["conditional_receiver_manifest_sha256"]):
        raise ValueError("conditional receiver manifest does not match its pin")
    release = json.loads(subprocess.check_output([
        "gh", "api", f"repos/{pin['repository']}/releases/{pin['release_id']}"
    ]))
    if not release["draft"]:
        raise ValueError("CI corpus must remain an unpublished draft")
    asset = pin["domains"][domain]
    output.mkdir(parents=True, exist_ok=False)
    archive_path = output.parent / f"{domain}-inputs.tar.gz"
    with archive_path.open("wb") as stream:
        subprocess.run([
            "gh", "api", "-H", "Accept: application/octet-stream",
            f"repos/{pin['repository']}/releases/assets/{asset['asset_id']}",
        ], stdout=stream, check=True)
    hasher = hashlib.sha256()
    with archive_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    if hasher.hexdigest() != asset["sha256"]:
        raise ValueError("corpus archive hash mismatch")
    records = next(d for d in json.loads(raw_manifest)["domains"] if d["id"] == domain)["records"]
    required = {h for r in records for h in (r["normal"], r["kernel"]) if h}
    seen = set()
    inventory_seen = False
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            if not member.isfile() or member.size > 64 * 1024 * 1024:
                raise ValueError(f"invalid corpus member: {member.name}")
            with archive.extractfile(member) as stream:
                data = stream.read()
            if member.name == "inventory.json":
                if inventory_seen or data != raw_manifest:
                    raise ValueError("corpus inventory mismatch or duplicate")
                inventory_seen = True
                continue
            if not re.fullmatch(r"[0-9a-f]{64}\.enc", member.name):
                raise ValueError(f"unexpected corpus member: {member.name}")
            expected = member.name[:-4]
            if expected not in required or expected in seen:
                raise ValueError(f"unexpected or duplicate component: {expected}")
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"component hash mismatch: {expected}")
            (output / member.name).write_bytes(data)
            seen.add(expected)
    if not inventory_seen or seen != required:
        raise ValueError("incomplete corpus")
    archive_path.unlink()
    if raw_conditional is not None:
        supplement = pin["supplemental_receivers"]
        expected_members = set(supplement["components"])
        supplemental_path = output.parent / supplement["file"]
        with supplemental_path.open("wb") as stream:
            subprocess.run([
                "gh", "api", "-H", "Accept: application/octet-stream",
                f"repos/{pin['repository']}/releases/assets/{supplement['asset_id']}",
            ], stdout=stream, check=True)
        archive_bytes = supplemental_path.read_bytes()
        if (len(archive_bytes) != supplement["bytes"] or
                hashlib.sha256(archive_bytes).hexdigest() != supplement["sha256"]):
            raise ValueError("supplemental receiver archive pin mismatch")
        supplemental_seen = set()
        with tarfile.open(supplemental_path, "r:gz") as archive:
            for member in archive:
                if (not member.isfile() or member.size > 64 * 1024 * 1024 or
                        not re.fullmatch(r"[0-9a-f]{64}\.enc", member.name)):
                    raise ValueError(f"invalid supplemental member: {member.name}")
                expected = member.name[:-4]
                if expected not in expected_members or expected in supplemental_seen:
                    raise ValueError("unexpected or duplicate supplemental receiver")
                with archive.extractfile(member) as stream:
                    data = stream.read()
                if hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError("supplemental receiver component hash mismatch")
                destination = output / member.name
                if destination.exists() and destination.read_bytes() != data:
                    raise ValueError("supplemental component conflicts with original corpus")
                destination.write_bytes(data)
                supplemental_seen.add(expected)
        if supplemental_seen != expected_members:
            raise ValueError("incomplete supplemental receiver archive")
        supplemental_path.unlink()
        normals = {r["normal"] for r in records}
        contexts = json.loads(raw_conditional)["records"]
        for row in contexts:
            if row["normal"] not in normals:
                continue
            if row["packaged_kernel"] is not None:
                raise ValueError("supplemental context cannot claim a packaged Kernel")
            for receiver in row["receivers"]:
                if receiver["association"] != "conditional-receiver-context":
                    raise ValueError("unqualified receiver association")
                if not (output / f"{receiver['kernel']}.enc").is_file():
                    raise ValueError("conditional receiver missing from exact inputs")
        print("Prepared separately pinned conditional receivers; installed Kernel remains unknown.")
    print(f"Prepared exact {domain} corpus: {len(seen)} components.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--domain", choices=["sat1", "h8sat"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--conditional-manifest", type=Path)
    args = parser.parse_args()
    fetch(args.config, args.manifest, args.domain, args.output, args.conditional_manifest)
