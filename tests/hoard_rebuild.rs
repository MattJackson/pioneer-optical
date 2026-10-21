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
    encode_encrypted_pair, encode_kernel_envelope, encode_kernel_envelope_with_header,
    encode_normal_for_kernel, normal_authentication_from_kernel, normal_rotation_from_kernel,
    BuildInputs, KernelBuild, KernelKeySource, NormalAuthentication, NormalKeySource,
    NormalRotation, NormalSignature, DERIVED_NORMAL_PAD_LEN, NORMAL_SIGNATURE_RANGE,
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
    /// Template-free rebuild failed (cause), but the body encoders reproduce
    /// both files exactly behind the OEM 0x200-byte headers; `raw_key` when
    /// the Normal key table is not LCG-derived and is supplied verbatim, and
    /// `signed` when exactness is signature-modulo as above.
    HeaderExact {
        cause: String,
        raw_key: bool,
        signed: bool,
    },
    /// Failure cause and detail.
    Failed(String, String),
}

/// Rebuild both bodies behind the OEM headers (opaque header bytes and
/// filename included) with the OEM seed, or the OEM key table when it is
/// not LCG-derived. `Ok(raw_key)` when both envelopes are reproduced.
fn rebuild_behind_oem_headers(pair: &Pair, signer: &SigningKey) -> Result<bool, String> {
    let k = decode_envelope(&pair.kernel).ok_or("kernel undecodable")?;
    let kraw = pair.kernel[0x200..0x1200].to_vec();
    let kkey = k
        .encoding_seed()
        .map_or(KernelKeySource::RawKey(&kraw), KernelKeySource::Seed);
    let kernel = encode_kernel_envelope_with_header(&k.image, &pair.kernel[..0x200], kkey)
        .map_err(|e| format!("kernel: {e}"))?;
    if let Some(d) = diff(&kernel, &pair.kernel) {
        return Err(format!("kernel {d}"));
    }
    let n = decode_envelope_with_kernel(&pair.normal, &k).ok_or("normal undecodable")?;
    let key_start = 0x200
        + if k.info().layout == Layout::KernelDerived {
            DERIVED_NORMAL_PAD_LEN
        } else {
            0
        };
    let raw = &pair.normal[key_start..n.info().payload_offset];
    let (key, raw_key) = match n.encoding_seed() {
        Some(seed) => (NormalKeySource::Seed(seed), false),
        None => (NormalKeySource::RawKey(raw), true),
    };
    let oem_sig = pair.normal[NORMAL_SIGNATURE_RANGE].to_vec();
    let header = &pair.normal[..0x200];
    let stamped = encode_normal_for_kernel(
        &k.image,
        &n.image,
        header,
        key,
        NormalSignature::Oem(&oem_sig),
    )
    .map_err(|e| format!("normal: {e}"))?;
    if let Some(d) = diff(&stamped, &pair.normal) {
        return Err(format!("normal {d}"));
    }
    if matches!(
        normal_authentication_from_kernel(&k.image),
        Some(NormalAuthentication::KeyAndCiphertext | NormalAuthentication::CiphertextOnly)
    ) {
        let fresh = encode_normal_for_kernel(
            &k.image,
            &n.image,
            header,
            key,
            NormalSignature::Sign(signer),
        )
        .map_err(|e| format!("normal fresh: {e}"))?;
        if diff_outside_signature(&fresh, &pair.normal).is_some()
            || !matches!(
                verify_normal_signature(&fresh),
                SignatureCheck::ValidKeyAndCiphertext | SignatureCheck::ValidCiphertextOnly
            )
        {
            return Err("fresh signature".into());
        }
    }
    Ok(raw_key)
}

/// Rebuild one OEM pair through the public builder and classify the result.
pub fn rebuild(pair: &Pair, signer: &SigningKey) -> Outcome {
    match rebuild_template_free(pair, signer) {
        Outcome::Failed(cause, detail) => match rebuild_behind_oem_headers(pair, signer) {
            Ok(raw_key) => Outcome::HeaderExact {
                cause,
                raw_key,
                signed: matches!(
                    decode_envelope(&pair.kernel)
                        .and_then(|k| normal_authentication_from_kernel(&k.image)),
                    Some(
                        NormalAuthentication::KeyAndCiphertext
                            | NormalAuthentication::CiphertextOnly
                    )
                ),
            },
            Err(why) => Outcome::Failed(cause, format!("{detail}; behind OEM headers: {why}")),
        },
        other => other,
    }
}

fn rebuild_template_free(pair: &Pair, signer: &SigningKey) -> Outcome {
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
    // This KAT measures continuous signed-file rebuilding. A spliced file
    // includes foreign ciphertext blocks which the image-only builder cannot
    // recreate. Still require the lossless envelope repacker to preserve it.
    if !n.spliced_blocks().is_empty() {
        assert_eq!(n.repack(&n.image).unwrap(), pair.normal, "{}", pair.label);
        return Outcome::OutOfScope("spliced Normal (lossless repack checked)".into());
    }
    // The hoard also contains reconstruction placeholders. Their absent
    // signature is not an OEM signature oracle. The separate property test
    // below still re-encodes their bodies with fresh signatures and raw keys.
    if n.signature_bytes()
        .is_some_and(|bytes| bytes.iter().all(|b| *b == 0))
        && matches!(
            normal_authentication_from_kernel(&k.image),
            Some(NormalAuthentication::KeyAndCiphertext | NormalAuthentication::CiphertextOnly)
        )
    {
        assert_eq!(n.repack(&n.image).unwrap(), pair.normal, "{}", pair.label);
        return Outcome::OutOfScope("Normal reconstruction placeholder (absent signature)".into());
    }
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
    let mut header_exact = BTreeMap::<String, Vec<String>>::new();
    let mut out_of_scope = BTreeMap::<String, usize>::new();
    let mut failures = BTreeMap::<String, Vec<String>>::new();
    for pair in &pairs {
        match rebuild(pair, &signer) {
            Outcome::OutOfScope(layout) => *out_of_scope.entry(layout).or_default() += 1,
            Outcome::Exact => exact += 1,
            Outcome::SignatureModuloExact => modulo += 1,
            Outcome::HeaderExact {
                cause,
                raw_key,
                signed,
            } => header_exact
                .entry(format!(
                    "{}{}",
                    if signed {
                        "signature-modulo-exact"
                    } else {
                        "exact"
                    },
                    if raw_key { " with raw Normal key" } else { "" }
                ))
                .or_default()
                .push(format!("{} :: template-free cause: {cause}", pair.label)),
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
    for (class, items) in &header_exact {
        eprintln!("behind OEM headers, {class}: {}", items.len());
        for item in items {
            eprintln!("    {item}");
        }
    }
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

/// `decode(encode(decode(x))) == decode(x)` for every SAT Normal, and the
/// receiver-policy round trip: a body encoded with a Kernel's rules decodes
/// back to that body with its decode. Gated by `PIONEER_HOARD_ROOT`.
#[test]
fn hoard_round_trip_properties_when_configured() {
    let Ok(root) = std::env::var("PIONEER_HOARD_ROOT") else {
        return;
    };
    let pairs = hoard_pairs(&PathBuf::from(root));
    let signer = SigningKey::from_bytes([9; 20]).unwrap();
    let mut checked = 0;
    let mut skipped = 0;
    for pair in &pairs {
        let Some(k) = decode_envelope(&pair.kernel) else {
            skipped += 1;
            continue;
        };
        if !matches!(k.info().layout, Layout::KernelFront | Layout::KernelDerived) {
            skipped += 1;
            continue;
        }
        let Some(n) = decode_envelope_with_kernel(&pair.normal, &k) else {
            skipped += 1;
            continue;
        };
        if normal_rotation_from_kernel(&k.image).is_none() {
            skipped += 1;
            continue;
        }
        // Re-encode the decoded body for this same Kernel, then decode again.
        let header = &pair.normal[..0x200];
        let key_start = 0x200
            + if k.info().layout == Layout::KernelDerived {
                DERIVED_NORMAL_PAD_LEN
            } else {
                0
            };
        let raw = &pair.normal[key_start..n.info().payload_offset];
        let key = n
            .encoding_seed()
            .map_or(NormalKeySource::RawKey(raw), NormalKeySource::Seed);
        let signed = matches!(
            normal_authentication_from_kernel(&k.image),
            Some(NormalAuthentication::KeyAndCiphertext | NormalAuthentication::CiphertextOnly)
        );
        let sig = if signed {
            NormalSignature::Sign(&signer)
        } else {
            NormalSignature::Zeroed
        };
        // Spliced OEM Normals do not carry their whole image, so encoding the
        // recovered image is a different, longer body; skip those here.
        if !n.spliced_blocks().is_empty() {
            skipped += 1;
            continue;
        }
        let re = encode_normal_for_kernel(&k.image, &n.image, header, key, sig)
            .unwrap_or_else(|e| panic!("{}: {e}", pair.label));
        let re_decoded = decode_envelope_with_kernel(&re, &k)
            .unwrap_or_else(|| panic!("{}: re-encoded body does not decode", pair.label));
        // decode(encode(decode(x))) == decode(x), and the image is checksum-zero.
        assert_eq!(re_decoded.image, n.image, "{}", pair.label);
        assert!(
            re_decoded.image.chunks_exact(4).fold(0u32, |s, w| s
                .wrapping_add(u32::from_be_bytes(w.try_into().unwrap())))
                == 0,
            "{}: BE32 checksum not zero",
            pair.label
        );
        // Receiver-policy round trip: the re-encoded envelope decodes with K's
        // rules to the same body, and carries the receiver XOR policy.
        assert!(
            re_decoded.receiver_xor_exceptions().is_some(),
            "{}: no receiver policy",
            pair.label
        );
        checked += 1;
    }
    eprintln!("round-trip properties held for {checked} pairs ({skipped} skipped)");
    assert!(checked > 100);
}

/// Cross-receiver re-encode: the BDR-PR1ML 1.30 Normal body, re-packed for the
/// BDR-207M 1.60 Kernel's transport, decodes with the 207M Kernel's rules to
/// the identical PR1ML body with a zero BE32 checksum. Gated by the two paths.
#[test]
fn pr1ml_body_reencoded_for_207m_receiver_when_configured() {
    let (Ok(pr1ml_path), Ok(k207_path)) = (
        std::env::var("PIONEER_PR1ML_130_TAR"),
        std::env::var("PIONEER_207M_160_TAR"),
    ) else {
        return;
    };
    let pr1ml = tar_members(&std::fs::read(pr1ml_path).unwrap());
    let k207m = tar_members(&std::fs::read(k207_path).unwrap());
    // Pick components by decoded role, not by filename: the 207M Kernel and
    // Normal carry different revisions in their names.
    let role_member = |members: &[(String, Vec<u8>)], kind| {
        members
            .iter()
            .find(|(_, d)| header_info(d).and_then(|h| h.kind) == Some(kind))
            .map(|(_, d)| d.clone())
            .unwrap()
    };
    let pr1ml_kernel_enc = role_member(&pr1ml, pioneer_optical::ComponentKind::Kernel);
    let pr1ml_normal_enc = role_member(&pr1ml, pioneer_optical::ComponentKind::Normal);
    let k207_kernel_enc = role_member(&k207m, pioneer_optical::ComponentKind::Kernel);
    let k207_normal_enc = role_member(&k207m, pioneer_optical::ComponentKind::Normal);

    let pr1ml_kernel = decode_envelope(&pr1ml_kernel_enc).unwrap();
    let pr1ml_body = decode_envelope_with_kernel(&pr1ml_normal_enc, &pr1ml_kernel).unwrap();
    let k207 = decode_envelope(&k207_kernel_enc).unwrap();
    assert_eq!(k207.info().model, "BDR-207M");
    assert_eq!(pr1ml_kernel.info().model, "BDR-PR1ML");
    // The two receivers differ: PR1ML reverses the rotation, 207M does not.
    assert_eq!(
        normal_rotation_from_kernel(&pr1ml_kernel.image),
        Some(NormalRotation::Reverse)
    );
    assert_eq!(
        normal_rotation_from_kernel(&k207.image),
        Some(NormalRotation::Forward)
    );

    // Re-encode the PR1ML body for the 207M receiver, using the 207M Normal's
    // own header so the envelope identifies as a 207M component.
    let header_207 = k207_normal_enc[..0x200].to_vec();
    let signer = SigningKey::from_bytes([3; 20]).unwrap();
    let reencoded = encode_normal_for_kernel(
        &k207.image,
        &pr1ml_body.image,
        &header_207,
        NormalKeySource::Seed(0x5a_5a5a),
        NormalSignature::Sign(&signer),
    )
    .expect("PR1ML body re-encodes for the 207M receiver");

    // Decoding with the 207M Kernel's rules yields the identical PR1ML body.
    let decoded = decode_envelope_with_kernel(&reencoded, &k207).unwrap();
    assert_eq!(
        decoded.image, pr1ml_body.image,
        "cross-receiver body differs"
    );
    let checksum = decoded.image.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    assert_eq!(
        checksum, 0,
        "re-decoded PR1ML body BE32 checksum is not zero"
    );

    // A valid signature is produced under the envelope's own scheme (the 207M
    // front-key receiver signs the key table and ciphertext from 0x200). It is
    // a caller-owned key, not the OEM public point.
    assert_eq!(
        verify_normal_signature(&reencoded),
        SignatureCheck::ValidKeyAndCiphertext
    );
    eprintln!(
        "PR1ML->207M: {} bytes, body {:#x}, checksum 0, signature valid (key-and-ciphertext, caller key)",
        reencoded.len(),
        decoded.image.len()
    );
}
