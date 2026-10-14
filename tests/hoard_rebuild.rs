//! Byte-exact rebuild KAT over every distinct Kernel+Normal pair in a firmware
//! hoard, without distributing firmware. Gated by `PIONEER_HOARD_ROOT`, the
//! directory holding `index/packages.json` and the `.installer.tar` packages.
//!
//! Each OEM envelope is decoded, then rebuilt through the public builder from
//! only its decoded image, its textual header fields, its LCG encoding seed and
//! (for signed Normals) its 0x50-byte OEM signature block. Classes:
//! - `exact`: every byte equals the OEM file, signature included.
//! - `signature-modulo-exact`: a signed Normal whose rebuilt bytes equal the
//!   OEM file outside `NORMAL_SIGNATURE_RANGE` when freshly signed, the fresh
//!   signature verifies under the envelope's scheme, and the stamped OEM
//!   signature verifies over the rebuilt body (so stamping it is byte-exact).
#![cfg(feature = "envelope")]

use pioneer_optical::envelope::builder::{
    encode_encrypted_pair, encode_kernel_envelope, normal_authentication_from_kernel,
    normal_rotation_from_kernel, BuildInputs, KernelBuild, KernelKeySource, NormalAuthentication,
    NormalRotation, NormalSignature, NORMAL_SIGNATURE_RANGE,
};
use pioneer_optical::envelope::signature::{verify_normal_signature, SignatureCheck, SigningKey};
use pioneer_optical::envelope::{
    decode_envelope, decode_envelope_with_kernel, header_info, Layout,
};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

fn tar_members(tar: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 512 <= tar.len() {
        let h = &tar[at..at + 512];
        if h.iter().all(|b| *b == 0) {
            break;
        }
        let cstr = |b: &[u8]| {
            String::from_utf8_lossy(&b[..b.iter().position(|c| *c == 0).unwrap_or(b.len())])
                .into_owned()
        };
        let mut name = cstr(&h[..100]);
        let prefix = cstr(&h[345..500]);
        if !prefix.is_empty() {
            name = format!("{prefix}/{name}");
        }
        let size = usize::from_str_radix(cstr(&h[124..136]).trim(), 8).unwrap_or(0);
        let data = tar[at + 512..at + 512 + size].to_vec();
        if h[156] == b'0' || h[156] == 0 {
            out.push((name, data));
        }
        at += 512 + size.div_ceil(512) * 512;
    }
    out
}

pub struct Pair {
    pub kernel: Vec<u8>,
    pub normal: Vec<u8>,
    pub label: String,
}

/// Every distinct (Kernel sha, Normal sha) pair the hoard index lists.
pub fn hoard_pairs(root: &Path) -> Vec<Pair> {
    let index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("index/packages.json")).unwrap()).unwrap();
    let mut seen = HashSet::new();
    let mut pairs = Vec::new();
    for p in index["packages"].as_array().unwrap() {
        let (Some(ks), Some(ns)) = (p["kernel_sha256"].as_str(), p["normal_sha256"].as_str())
        else {
            continue;
        };
        if !seen.insert((ks.to_string(), ns.to_string())) {
            continue;
        }
        let members = tar_members(&std::fs::read(root.join(p["path"].as_str().unwrap())).unwrap());
        let find = |role: &str| {
            let member = p["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["role"] == role)
                .and_then(|c| c["member"].as_str())
                .unwrap();
            members
                .iter()
                .find(|(n, _)| n == member)
                .map(|(_, d)| d.clone())
                .unwrap()
        };
        pairs.push(Pair {
            kernel: find("kernel"),
            normal: find("normal"),
            label: format!(
                "{} {} {} {} k={} n={}",
                p["embedded_model"].as_str().unwrap_or("?"),
                p["hardware_version"].as_str().unwrap_or("?"),
                p["destination"].as_str().unwrap_or("?"),
                p["revision"].as_str().unwrap_or("?"),
                &ks[..8],
                &ns[..8]
            ),
        });
    }
    pairs
}

fn region(offset: usize) -> &'static str {
    match offset {
        0..=0x15f => "text-header",
        0x160..=0x16f => "prevalidation",
        0x170..=0x1bf => "signature",
        0x1c0..=0x1ef => "extension",
        0x1f0..=0x1ff => "filename",
        _ => "body",
    }
}

fn diff(a: &[u8], b: &[u8]) -> Option<String> {
    if a == b {
        return None;
    }
    if a.len() != b.len() {
        return Some(format!("length {:#x} vs OEM {:#x}", a.len(), b.len()));
    }
    let first = a.iter().zip(b).position(|(x, y)| x != y).unwrap();
    let count = a.iter().zip(b).filter(|(x, y)| x != y).count();
    Some(format!("{} at {first:#x} ({count} bytes)", region(first)))
}

fn diff_outside_signature(a: &[u8], b: &[u8]) -> Option<String> {
    if a.len() != b.len() {
        return diff(a, b);
    }
    let mut a = a.to_vec();
    a[NORMAL_SIGNATURE_RANGE].copy_from_slice(&b[NORMAL_SIGNATURE_RANGE]);
    diff(&a, b)
}

fn kernel_build<'a>(
    header: &'a pioneer_optical::envelope::HeaderInfo,
    seed: Option<u32>,
    raw: &'a [u8],
) -> KernelBuild<'a> {
    KernelBuild {
        revision: &header.revision,
        date: &header.generated_date,
        key: seed.map_or(KernelKeySource::RawKey(raw), KernelKeySource::Seed),
    }
}

/// Outcome of rebuilding one OEM pair.
pub enum Outcome {
    /// Not a SAT-era front/derived-key Kernel; named by its layout.
    OutOfScope(String),
    Exact,
    SignatureModuloExact,
    /// Failure cause and detail.
    Failed(String, String),
}

/// Rebuild one OEM pair through the public builder and classify the result.
pub fn rebuild(pair: &Pair, signer: &SigningKey) -> Outcome {
    let Some(k) = decode_envelope(&pair.kernel) else {
        let hw = header_info(&pair.kernel).map_or("?".into(), |h| h.hardware_version);
        if !hw.starts_with("SAT ") {
            return Outcome::OutOfScope(format!("{hw} undecodable"));
        }
        return Outcome::Failed("kernel-undecodable".into(), hw);
    };
    let layout = k.info().layout;
    if !matches!(layout, Layout::KernelFront | Layout::KernelDerived) {
        return Outcome::OutOfScope(layout.to_string());
    }
    let mut causes = Vec::new();
    let mut details = Vec::new();
    let kh = header_info(&pair.kernel).unwrap();
    let kseed = k.encoding_seed();
    let kraw = pair.kernel[0x200..0x1200].to_vec();
    match encode_kernel_envelope(&k.image, &kh.id, &kernel_build(&kh, kseed, &kraw)) {
        Ok(rebuilt) => {
            if let Some(d) = diff(&rebuilt, &pair.kernel) {
                causes.push(format!("kernel-{layout}-drift"));
                details.push(d);
            }
        }
        Err(e) => causes.push(format!("kernel-{layout}-error: {e}")),
    }
    let Some(n) = decode_envelope_with_kernel(&pair.normal, &k) else {
        let plain = decode_envelope(&pair.normal).map(|n| n.info().layout.to_string());
        causes.push("normal-receiver-undecodable".into());
        details.push(format!("framing-only layout {plain:?}"));
        return Outcome::Failed(causes.join(" + "), details.join("; "));
    };
    let nlayout = n.info().layout;
    let predicted = normal_rotation_from_kernel(&k.image);
    let observed = match nlayout {
        Layout::NormalReverse => Some(NormalRotation::Reverse),
        Layout::Normal | Layout::NormalScaledKey => Some(NormalRotation::Forward),
        _ => None,
    };
    if predicted != observed {
        causes.push(format!("rotation-{predicted:?}-vs-{nlayout}"));
    }
    let nh = header_info(&pair.normal).unwrap();
    let Some(nseed) = n.encoding_seed() else {
        causes.push(format!("normal-{nlayout}-non-lcg-key"));
        return Outcome::Failed(causes.join(" + "), details.join("; "));
    };
    let policy = normal_authentication_from_kernel(&k.image);
    let signed = matches!(
        policy,
        Some(NormalAuthentication::KeyAndCiphertext | NormalAuthentication::CiphertextOnly)
    );
    let oem_sig = pair.normal[NORMAL_SIGNATURE_RANGE].to_vec();
    let inputs = BuildInputs {
        kernel_image: &k.image,
        normal_image: &n.image,
        envelope_id: &nh.id,
        normal_revision: &nh.revision,
        normal_date: &nh.generated_date,
        kernel: kernel_build(&kh, kseed, &kraw),
        normal_key_seed: nseed,
    };
    let stamped = match encode_encrypted_pair(&inputs, NormalSignature::Oem(&oem_sig)) {
        Ok(p) => p.normal,
        Err(e) => {
            let zeroed = encode_encrypted_pair(&inputs, NormalSignature::Zeroed)
                .map(|p| diff_outside_signature(&p.normal, &pair.normal));
            causes.push(format!("normal-{nlayout}-error: {e}"));
            details.push(format!("policy {policy:?}; zeroed rebuild {zeroed:?}"));
            return Outcome::Failed(causes.join(" + "), details.join("; "));
        }
    };
    if let Some(d) = diff_outside_signature(&stamped, &pair.normal) {
        causes.push(format!("normal-{nlayout}-drift"));
        details.push(d);
    } else if stamped != pair.normal {
        causes.push(format!("normal-{nlayout}-signature-region"));
    }
    if !causes.is_empty() {
        return Outcome::Failed(causes.join(" + "), details.join("; "));
    }
    if !signed {
        return Outcome::Exact;
    }
    // Signed: the OEM block stamped over the rebuilt body must verify, and a
    // fresh signature over the same body must verify under the same scheme.
    let expected = match policy {
        Some(NormalAuthentication::KeyAndCiphertext) => SignatureCheck::ValidKeyAndCiphertext,
        _ => SignatureCheck::ValidCiphertextOnly,
    };
    let fresh = encode_encrypted_pair(&inputs, NormalSignature::Sign(signer)).unwrap();
    if verify_normal_signature(&stamped) == expected
        && verify_normal_signature(&fresh.normal) == expected
        && diff_outside_signature(&fresh.normal, &pair.normal).is_none()
    {
        Outcome::SignatureModuloExact
    } else {
        Outcome::Failed(
            format!("normal-{nlayout}-signature"),
            format!(
                "oem {:?} fresh {:?}",
                verify_normal_signature(&stamped),
                verify_normal_signature(&fresh.normal)
            ),
        )
    }
}

#[test]
fn every_hoard_pair_rebuilds_byte_exact_when_configured() {
    let Ok(root) = std::env::var("PIONEER_HOARD_ROOT") else {
        return;
    };
    let pairs = hoard_pairs(&PathBuf::from(root));
    let signer = SigningKey::from_bytes([7; 20]).unwrap();
    let (mut exact, mut modulo) = (0, 0);
    let mut out_of_scope = BTreeMap::<String, usize>::new();
    let mut failures = BTreeMap::<String, Vec<String>>::new();
    for pair in &pairs {
        match rebuild(pair, &signer) {
            Outcome::OutOfScope(layout) => *out_of_scope.entry(layout).or_default() += 1,
            Outcome::Exact => exact += 1,
            Outcome::SignatureModuloExact => modulo += 1,
            Outcome::Failed(cause, detail) => failures
                .entry(cause)
                .or_default()
                .push(format!("{} :: {detail}", pair.label)),
        }
    }
    let failed: usize = failures.values().map(Vec::len).sum();
    let skipped: usize = out_of_scope.values().sum();
    eprintln!(
        "hoard rebuild: {} distinct pairs; {skipped} out of scope; {} SAT pairs; {exact} exact; {modulo} signature-modulo-exact; {failed} failed",
        pairs.len(),
        pairs.len() - skipped,
    );
    for (class, n) in &out_of_scope {
        eprintln!("out of scope: {class}: {n}");
    }
    for (class, items) in &failures {
        eprintln!("FAIL {class}: {}", items.len());
        for item in items {
            eprintln!("    {item}");
        }
    }
    if std::env::var_os("PIONEER_HOARD_ALLOW_FAILURES").is_none() {
        assert_eq!(failed, 0, "hoard pairs failed to rebuild");
    }
}
