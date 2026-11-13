//! Golden-output oracle for the pioneer-optical clean-reimplementation effort.
//!
//! Pure characterization: run the CURRENT library's observable transforms over
//! a corpus of firmware component files and emit a deterministic JSON manifest
//! (hashes + identity fields, never raw firmware bytes). The clean rewrite must
//! reproduce this manifest byte-for-byte across the whole corpus.
//!
//! Usage: `cargo run --release --features envelope --example oracle -- <dir> [<dir> ...]`
//! Input: directories of raw Pioneer component files (`*.enc`, or the `kernel.enc`
//! / `normal.enc` members already extracted under the firmware-extractor hoard).

use pioneer_optical::envelope::{decode_envelope, Envelope};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn record(bytes: &[u8]) -> BTreeMap<&'static str, String> {
    let mut row = BTreeMap::new();
    row.insert("input_sha256", sha(bytes));
    row.insert("input_len", bytes.len().to_string());
    match decode_envelope(bytes) {
        Some(decoded) => {
            row.insert("decode", "ok".into());
            row.insert("image_sha256", sha(&decoded.image));
            row.insert("image_len", decoded.image.len().to_string());
            let info = decoded.header_info();
            row.insert("kind", format!("{:?}", info.kind));
            row.insert("id", info.id);
            row.insert("model", info.model);
            row.insert("revision", info.revision);
            row.insert("hardware_version", info.hardware_version);
            row.insert("kernel_version", info.kernel_version);
        }
        None => {
            row.insert("decode", "none".into());
        }
    }
    // Round-trip: load as a signed Envelope, repack its own image, expect identical bytes.
    match Envelope::load(bytes) {
        Ok(env) => {
            row.insert("envelope_load", "ok".into());
            match env.repack(&env.image) {
                Some(repacked) => {
                    row.insert("repack_sha256", sha(&repacked));
                    row.insert("repack_roundtrip_equal", (repacked == bytes).to_string());
                }
                None => {
                    row.insert("repack", "none".into());
                }
            }
        }
        Err(error) => {
            row.insert("envelope_load", format!("err:{error:?}"));
        }
    }
    row
}

fn walk(dir: &Path, out: &mut BTreeMap<String, BTreeMap<&'static str, String>>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "enc" || e == "bin") {
            if let Ok(bytes) = std::fs::read(&path) {
                out.insert(path.to_string_lossy().into_owned(), record(&bytes));
            }
        }
    }
}

fn main() {
    let mut out: BTreeMap<String, BTreeMap<&'static str, String>> = BTreeMap::new();
    for arg in std::env::args().skip(1) {
        walk(Path::new(&arg), &mut out);
    }
    // Deterministic, keyed by file basename+sha so corpus path moves don't churn it.
    let mut keyed: BTreeMap<String, &BTreeMap<&'static str, String>> = BTreeMap::new();
    for (path, row) in &out {
        let base = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        keyed.insert(format!("{}:{}", base, &row["input_sha256"][..16]), row);
    }
    println!("{}", serde_json::to_string_pretty(&keyed).unwrap());
    eprintln!("oracle: {} files characterized", out.len());
}
