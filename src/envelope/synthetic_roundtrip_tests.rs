use super::builder::*;
use super::signature::{verify_normal_signature, SignatureCheck, SigningKey};
use super::*;

/// Set a word so the big-endian 32-bit sum over `buf` is zero.
fn be32_fix(buf: &mut [u8], fix_at: usize) {
    buf[fix_at..fix_at + 4].copy_from_slice(&[0; 4]);
    let mut sum = 0u32;
    let mut i = 0;
    while i + 4 <= buf.len() {
        sum = sum.wrapping_add(u32::from_be_bytes([
            buf[i],
            buf[i + 1],
            buf[i + 2],
            buf[i + 3],
        ]));
        i += 4;
    }
    buf[fix_at..fix_at + 4].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
}

/// Write the exact single XOR-skipping branch that `kernel_xor_branches`
/// recognizes (target 20 variant), carrying two exception offsets.
fn write_branch(buf: &mut [u8], at: usize, offs: [u32; 2]) {
    buf[at] = 0x7a;
    buf[at + 1] = 0x20;
    buf[at + 2..at + 6].copy_from_slice(&offs[0].to_be_bytes());
    buf[at + 6] = 0x47;
    buf[at + 7] = 12;
    buf[at + 8] = 0x7a;
    buf[at + 9] = 0x20;
    buf[at + 10..at + 14].copy_from_slice(&offs[1].to_be_bytes());
    buf[at + 14] = 0x47;
    buf[at + 15] = 4;
    buf[at + 16..at + 20].copy_from_slice(&[1, 0xf0, 0x65, 5]);
}

fn header_bytes(file_type: &str, hardware: &str, destination: &str) -> [u8; 0x200] {
    let info = HeaderInfo {
        id: "PIONEER BDR-US04".into(),
        model: "BDR-US04".into(),
        revision: "1.00".into(),
        hardware_version: hardware.into(),
        kernel_version: "GENERAL".into(),
        destination: destination.into(),
        generated_date: "00/00/00".into(),
        kernel_version2: "0000".into(),
        kind: ComponentKind::from_header(file_type),
    };
    let opaque = HeaderOpaque {
        id_left_padding: 0,
        prevalidation: [0; 0x10],
        validation: [0; 0x50],
        extension: [0; 0x30],
        filename: [0; 0x10],
    };
    build_header(&info, &opaque).unwrap()
}

/// 0x10000 Kernel image with a FrontKey dispatcher (one AE compare pair),
/// the SAT identity block, and exactly one XOR-skip branch.
pub(super) fn front_kernel() -> Vec<u8> {
    let mut k = vec![0u8; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
    k[0x1010..0x1014].copy_from_slice(b"0000");
    // FrontKey dispatcher signature: one AE/FE .. AE/F0 compare pair.
    k[0x40] = 0xae;
    k[0x41] = 0xfe;
    k[0x46] = 0xae;
    k[0x47] = 0xf0;
    write_branch(&mut k, 0x100, [0x100, 0x200]);
    be32_fix(&mut k, 0xff00);
    k
}

/// As `front_kernel`, but the DerivedKey dispatcher (one AD compare pair).
fn derived_kernel() -> Vec<u8> {
    let mut k = vec![0u8; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
    k[0x1010..0x1014].copy_from_slice(b"0000");
    k[0x40] = 0xad;
    k[0x41] = 0xfe;
    k[0x46] = 0xad;
    k[0x47] = 0xf0;
    write_branch(&mut k, 0x100, [0x100, 0x200]);
    be32_fix(&mut k, 0xff00);
    k
}

/// 0x10000 Kernel image carrying the legacy decoder call site and the
/// scaled-geometry recognizer window (image 0x2000, key 0x200).
fn scaled_kernel() -> Vec<u8> {
    let mut k = vec![0u8; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
    k[0x1010..0x1014].copy_from_slice(b"0000");

    // Legacy decoder call site at L: the "long length" prelude, the fixed
    // argument block, and the jsr whose target (0x400100) resolves inside
    // the kernel image.
    const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
    let l = 0x300;
    k[l - 6..l].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
    k[l..l + 12].copy_from_slice(&ARGS);
    k[l + 12..l + 16].copy_from_slice(&[0x5e, 0x40, 0x01, 0x00]);

    // Scaled geometry window at M. envelope=0x2400, key+0x10400=0x10600,
    // image=0x2000; decoder word matches the call above.
    let m = 0x400;
    k[m] = 0x7a;
    k[m + 1] = 0x21;
    k[m + 2..m + 6].copy_from_slice(&0x2400u32.to_be_bytes());
    k[m + 6] = 0x58;
    k[m + 7] = 0x60;
    k[m + 10] = 0x7a;
    k[m + 11] = 0;
    k[m + 12..m + 16].copy_from_slice(&0x10600u32.to_be_bytes());
    k[m + 16] = 0x7a;
    k[m + 17] = 1;
    k[m + 18..m + 22].copy_from_slice(&0x2000u32.to_be_bytes());
    k[m + 22..m + 28].copy_from_slice(&[0x7a, 2, 0, 1, 4, 0]);
    k[m + 28..m + 32].copy_from_slice(&[0x5e, 0x40, 0x01, 0x00]);

    write_branch(&mut k, 0x500, [0x100, 0x200]);
    be32_fix(&mut k, 0xff00);
    k
}

pub(super) fn normal_image(len: usize) -> Vec<u8> {
    let mut n = vec![0u8; len];
    n[..8].copy_from_slice(b"PIONEER ");
    n[20..24].copy_from_slice(&(len as u32).to_be_bytes());
    be32_fix(&mut n, len - 0x100);
    n
}

fn signer() -> SigningKey {
    let mut private = [0u8; 20];
    private[19] = 5;
    SigningKey::from_bytes(private).unwrap()
}

#[test]
fn frontkey_recognizers_classify_dispatcher_and_policy() {
    let kernel = front_kernel();
    assert_eq!(kernel_layout_from_image(&kernel), Some(Layout::KernelFront));
    assert_eq!(scaled_normal_geometry_from_kernel(&kernel), None);
    assert_eq!(
        normal_authentication_from_kernel(&kernel),
        Some(NormalAuthentication::KeyAndCiphertext)
    );
    assert_eq!(kernel_xor_branches(&kernel), vec![(0x100, [0x100, 0x200])]);
}

#[test]
fn derivedkey_dispatcher_classifies_as_ciphertext_only() {
    let kernel = derived_kernel();
    assert_eq!(
        kernel_layout_from_image(&kernel),
        Some(Layout::KernelDerived)
    );
    assert_eq!(
        normal_authentication_from_kernel(&kernel),
        Some(NormalAuthentication::CiphertextOnly)
    );
}

#[test]
fn scaled_kernel_recognizes_geometry_and_decoder() {
    let kernel = scaled_kernel();
    let geometry = scaled_normal_geometry_from_kernel(&kernel).unwrap();
    assert_eq!(geometry.image_len, 0x2000);
    assert_eq!(geometry.key_len, 0x200);
    assert_eq!(geometry.envelope_len, 0x2400);
    assert_eq!(
        normal_authentication_from_kernel(&kernel),
        Some(NormalAuthentication::ScaledChecksumOnly)
    );
    // Scaled kernels dispatch through the legacy decoder, so the layout
    // resolves as FrontKey from the decoder presence alone (no AE/AD pair).
    assert_eq!(kernel_layout_from_image(&kernel), Some(Layout::KernelFront));
}

#[test]
fn frontkey_keyandciphertext_pair_round_trips_and_detects_tamper() {
    let kernel = front_kernel();
    let normal = normal_image(0x2000);
    let s = signer();
    let input = BuildInputs {
        kernel_image: &kernel,
        normal_image: &normal,
        envelope_id: "PIONEER BDR-TEST",
        normal_revision: "1.00",
        normal_date: "00/00/00",
        kernel: KernelBuild::from_seed(0x123456),
        normal_key_seed: 0x47d001,
    };
    let pair = encode_encrypted_pair(&input, NormalSignature::Sign(&s)).unwrap();
    assert_eq!(pair.kernel.len(), 0x11200);
    assert_eq!(pair.normal.len(), 0x10200 + normal.len());
    validate_encrypted_pair(&pair, &kernel, &normal).unwrap();

    let dk = decode_envelope(&pair.kernel).unwrap();
    assert_eq!(dk.info.layout, Layout::KernelFront);
    assert_eq!(dk.image, kernel);
    assert_eq!(dk.encoding_seed(), Some(0x123456));

    let dn = decode_envelope_with_kernel(&pair.normal, &dk).unwrap();
    assert_eq!(dn.info.layout, Layout::Normal);
    assert_eq!(dn.image, normal);
    assert_eq!(
        dn.receiver_xor_exceptions(),
        Some([0x100u32, 0x200].as_slice())
    );
    assert_eq!(dn.encoding_seed(), Some(0x47d001));
    assert_eq!(
        verify_normal_signature(&pair.normal),
        SignatureCheck::ValidKeyAndCiphertext
    );
    assert!(normal_authentication_valid(&pair.normal, &kernel));

    // Flip the final ciphertext byte: signature must stop verifying and the
    // whole validation must fail.
    let mut tampered = pair.normal.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert_ne!(
        verify_normal_signature(&tampered),
        SignatureCheck::ValidKeyAndCiphertext
    );
    assert!(!normal_authentication_valid(&tampered, &kernel));
    let mut bad_pair = EncryptedPair {
        kernel: pair.kernel.clone(),
        normal: tampered,
    };
    assert!(validate_encrypted_pair(&bad_pair, &kernel, &normal).is_err());
    // Flip a Kernel byte: Kernel round trip must fail.
    bad_pair = EncryptedPair {
        kernel: {
            let mut k = pair.kernel.clone();
            k[0x1300] ^= 1;
            k
        },
        normal: pair.normal.clone(),
    };
    assert!(validate_encrypted_pair(&bad_pair, &kernel, &normal).is_err());
}

#[test]
fn derivedkey_ciphertext_only_pair_round_trips() {
    let kernel = derived_kernel();
    let normal = normal_image(0x2000);
    let s = signer();
    let input = BuildInputs {
        kernel_image: &kernel,
        normal_image: &normal,
        envelope_id: "PIONEER BDR-TEST",
        normal_revision: "1.00",
        normal_date: "00/00/00",
        kernel: KernelBuild::from_seed(0x123456),
        normal_key_seed: 0x47d001,
    };
    let pair = encode_encrypted_pair(&input, NormalSignature::Sign(&s)).unwrap();
    validate_encrypted_pair(&pair, &kernel, &normal).unwrap();

    let dk = decode_envelope(&pair.kernel).unwrap();
    assert_eq!(dk.info.layout, Layout::KernelDerived);
    assert_eq!(dk.image, kernel);
    assert_eq!(dk.encoding_seed(), Some(0x123456));

    let dn = decode_envelope_with_kernel(&pair.normal, &dk).unwrap();
    assert_eq!(dn.image, normal);
    assert_eq!(
        verify_normal_signature(&pair.normal),
        SignatureCheck::ValidCiphertextOnly
    );

    // A DerivedKey build cannot use raw key bytes.
    let raw = vec![0u8; 0x1000];
    let bad = KernelBuild {
        revision: "0000",
        date: "00/00/00",
        key: KernelKeySource::RawKey(&raw),
    };
    assert!(encode_kernel_envelope(&kernel, "PIONEER BDR-TEST", &bad).is_err());
}

#[test]
fn scaled_checksum_only_pair_round_trips() {
    let kernel = scaled_kernel();
    let normal = normal_image(0x2000);
    let input = BuildInputs {
        kernel_image: &kernel,
        normal_image: &normal,
        envelope_id: "PIONEER BDR-TEST",
        normal_revision: "1.00",
        normal_date: "00/00/00",
        kernel: KernelBuild::from_seed(0x123456),
        normal_key_seed: 0x47d001,
    };
    // ScaledChecksumOnly ignores the signature argument.
    let pair = encode_encrypted_pair(&input, NormalSignature::Zeroed).unwrap();
    assert_eq!(pair.normal.len(), 0x2400);
    validate_encrypted_pair(&pair, &kernel, &normal).unwrap();

    let dk = decode_envelope(&pair.kernel).unwrap();
    let dn = decode_envelope_with_kernel(&pair.normal, &dk).unwrap();
    assert_eq!(dn.info.layout, Layout::NormalScaledKey);
    assert_eq!(dn.image, normal);
    assert!(normal_authentication_valid(&pair.normal, &kernel));

    // Breaking the big-endian checksum of the Normal image fails ScaledChecksumOnly.
    let mut not_zero_sum = normal.clone();
    not_zero_sum[0x40] ^= 1;
    let bad = BuildInputs {
        normal_image: &not_zero_sum,
        ..input
    };
    assert!(encode_encrypted_pair(&bad, NormalSignature::Zeroed).is_err());
}

#[test]
fn frontkey_raw_key_matches_seed_expanded_key() {
    let kernel = front_kernel();
    let seed_enc = encode_kernel_envelope(
        &kernel,
        "PIONEER BDR-TEST",
        &KernelBuild::from_seed(0x123456),
    )
    .unwrap();
    let expanded = make_key(0x123456, 0x1000);
    let raw_enc = encode_kernel_envelope(
        &kernel,
        "PIONEER BDR-TEST",
        &KernelBuild {
            revision: "0000",
            date: "00/00/00",
            key: KernelKeySource::RawKey(&expanded),
        },
    )
    .unwrap();
    assert_eq!(seed_enc, raw_enc);
    // Wrong-length raw key is rejected.
    assert!(encode_kernel_envelope(
        &kernel,
        "PIONEER BDR-TEST",
        &KernelBuild {
            revision: "0000",
            date: "00/00/00",
            key: KernelKeySource::RawKey(&expanded[..0xfff]),
        },
    )
    .is_err());
}

#[test]
fn oem_and_zeroed_signature_modes_behave_as_documented() {
    let kernel = front_kernel();
    let normal = normal_image(0x2000);
    let s = signer();
    let input = BuildInputs {
        kernel_image: &kernel,
        normal_image: &normal,
        envelope_id: "PIONEER BDR-TEST",
        normal_revision: "1.00",
        normal_date: "00/00/00",
        kernel: KernelBuild::from_seed(0x123456),
        normal_key_seed: 0x47d001,
    };
    // Zeroed sentinel: skips ECDSA but still round-trips; signature region stays zero.
    let zeroed = encode_encrypted_pair(&input, NormalSignature::Zeroed).unwrap();
    assert!(zeroed.normal[NORMAL_SIGNATURE_RANGE]
        .iter()
        .all(|b| *b == 0));
    assert_eq!(
        verify_normal_signature(&zeroed.normal),
        SignatureCheck::Unsupported
    );
    // A signed Normal is not all-zero in the signature region.
    let signed = encode_encrypted_pair(&input, NormalSignature::Sign(&s)).unwrap();
    assert!(!signed.normal[NORMAL_SIGNATURE_RANGE]
        .iter()
        .all(|b| *b == 0));
    // Re-stamping the signed block as a verbatim OEM block reproduces it.
    let block = signed.normal[NORMAL_SIGNATURE_RANGE].to_vec();
    let oem = encode_encrypted_pair(&input, NormalSignature::Oem(&block)).unwrap();
    assert_eq!(oem.normal, signed.normal);
    // Wrong-size OEM block is rejected.
    assert!(encode_encrypted_pair(&input, NormalSignature::Oem(&block[..0x4f])).is_err());
}

#[test]
fn decode_with_kernel_passes_non_normal_through_unchanged() {
    // A Kernel envelope decoded with a kernel policy is returned verbatim.
    let kernel = front_kernel();
    let kernel_enc = encode_kernel_envelope(
        &kernel,
        "PIONEER BDR-TEST",
        &KernelBuild::from_seed(0x123456),
    )
    .unwrap();
    let dk = decode_envelope(&kernel_enc).unwrap();
    let again = decode_envelope_with_kernel(&kernel_enc, &dk).unwrap();
    assert_eq!(again.info.kind, ComponentKind::Kernel);
    assert_eq!(again.image, kernel);
    assert!(again.receiver_xor_exceptions().is_none());
}

#[test]
fn legacy_le_kernel_decodes_checksum_guarded_image() {
    let mut env = vec![0u8; 0x10000];
    env[..0x200].copy_from_slice(&header_bytes("Kernel", "SAT 8A10", "GENERAL"));
    env[0x200..0x9000].fill(0xff);
    let key: Vec<u8> = (0..0x500u32)
        .map(|i| (i.wrapping_mul(7).wrapping_add(1)) as u8)
        .collect();
    env[0x9000..0x9500].copy_from_slice(&key);
    env[0x9500..0xb000].fill(0xff);

    // Decoded image T: checksum word, 0xff gap, then a PIONEER tail whose
    // little-endian word sum (with the checksum) is zero.
    let mut image = vec![0u8; 0x5000];
    image[4..0x1000].fill(0xff);
    image[0x1000..0x1008].copy_from_slice(b"PIONEER ");
    let mut tail_sum = 0u32;
    let mut i = 0x1000;
    while i + 4 <= image.len() {
        tail_sum = tail_sum.wrapping_add(u32::from_le_bytes([
            image[i],
            image[i + 1],
            image[i + 2],
            image[i + 3],
        ]));
        i += 4;
    }
    image[..4].copy_from_slice(&0u32.wrapping_sub(tail_sum).to_le_bytes());
    let cipher = transform(&image, &key, true).unwrap();
    env[0xb000..].copy_from_slice(&cipher);

    let decoded = decode_envelope(&env).unwrap();
    assert_eq!(decoded.info.layout, Layout::KernelLegacyLe);
    assert_eq!(decoded.image, image);
    assert_eq!(decoded.repack(&decoded.image).unwrap(), env);

    // A single non-0xff byte in the reserved gap breaks recognition.
    let mut broken = env.clone();
    broken[0x9500] = 0;
    assert!(decode_envelope(&broken).is_none());
    // Corrupting the checksum makes the summed guard fail.
    let mut bad_sum = image.clone();
    bad_sum[0] ^= 1;
    let bad_cipher = transform(&bad_sum, &key, true).unwrap();
    let mut bad_env = env.clone();
    bad_env[0xb000..].copy_from_slice(&bad_cipher);
    assert!(decode_envelope(&bad_env).is_none());
}

#[test]
fn comp_streams_rejects_odd_and_overlong_directories() {
    let make = |addresses: &[u32]| -> Option<(u32, Vec<CompStream>)> {
        let mut image = vec![0xffu8; 0x4000];
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        for (i, a) in addresses.iter().enumerate() {
            image[0x1004 + i * 4..0x1008 + i * 4].copy_from_slice(&a.to_be_bytes());
        }
        comp_streams(&image)
    };
    // Odd number of addresses (not start/end pairs).
    assert!(make(&[0x410000, 0x412000, 0x414000]).is_none());
    // More than 32 addresses.
    let many: Vec<u32> = (0..34).map(|i| 0x410000 + i * 0x1000).collect();
    assert!(make(&many).is_none());
    // Empty directory.
    assert!(make(&[]).is_none());
}

fn zlib_at(data: &[u8], level: u32) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(level));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Build a valid COMP image located at `base`, one directory entry per
/// `(expanded, compression_level)`.
fn comp_image(base: u32, streams: &[(Vec<u8>, u32)]) -> Vec<u8> {
    let mut image = vec![0xffu8; 0x2000];
    image[..8].copy_from_slice(b"PIONEER ");
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    let mut offset = 0x2000usize;
    for (i, (exp, lvl)) in streams.iter().enumerate() {
        let comp = zlib_at(exp, *lvl);
        let end_off = offset + 4 + comp.len();
        if image.len() < end_off {
            image.resize(end_off, 0xff);
        }
        let start = base + offset as u32;
        let end = start + comp.len() as u32;
        image[0x1004 + i * 8..0x1008 + i * 8].copy_from_slice(&start.to_be_bytes());
        image[0x1008 + i * 8..0x100c + i * 8].copy_from_slice(&end.to_be_bytes());
        image[offset..offset + 4].copy_from_slice(&(exp.len() as u32).to_be_bytes());
        image[offset + 4..offset + 4 + comp.len()].copy_from_slice(&comp);
        offset = (end_off + 0xfff) & !0xfff;
    }
    let newlen = (image.len() + 0xff) & !0xff;
    image.resize(newlen, 0xff);
    let size = image.len() as u32;
    image[20..24].copy_from_slice(&size.to_be_bytes());
    image
}

/// A target-34 branch (second recognized form) carrying two offsets.
fn branch_t34(offs: [u32; 2]) -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[0] = 0x7a;
    b[1] = 0x20;
    b[2..6].copy_from_slice(&offs[0].to_be_bytes());
    b[6] = 0x47;
    b[7] = 26; // target1 = 8 + 26 = 34
    b[8] = 0x7a;
    b[9] = 0x20; // b[8..10] == b[..2]
    b[10..14].copy_from_slice(&offs[1].to_be_bytes());
    b[14] = 0x47;
    b[15] = 18; // target2 = 16 + 18 = 34
    b[16..34].copy_from_slice(&[
        0x01, 0, 0x69, 0x71, 0x01, 0, 0x6f, 0x70, 0, 4, 0x01, 0xf0, 0x65, 1, 0x01, 0, 0x69, 0xf1,
    ]);
    b
}

/// A WX1DM branch (the else-if form) carrying two offsets.
fn branch_wx1dm(offs: [u32; 2]) -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[0] = 0x7a;
    b[1] = 0x23;
    b[2..6].copy_from_slice(&offs[0].to_be_bytes());
    b[6] = 0x47;
    b[7..16].copy_from_slice(&[0x18, 1, 0, 0x6f, 0x73, 0, 0x0e, 0x7a, 0x23]);
    b[16..20].copy_from_slice(&offs[1].to_be_bytes());
    b[20..32].copy_from_slice(&[0x47, 0x0a, 1, 0, 0x6f, 0x70, 0, 0x18, 1, 0xf0, 0x65, 4]);
    b
}

#[test]
fn kernel_xor_branches_recognizer_guards() {
    // Opcode filter: a wrong b[0] (kept self-consistent at b[8]) must be
    // skipped; a `|| -> &&` on the filter would process and push it.
    let mut wrong_op = vec![0u8; 64];
    write_branch(&mut wrong_op, 0, [0x100, 0x200]);
    wrong_op[0] = 0x7b;
    wrong_op[8] = 0x7b;
    assert!(kernel_xor_branches(&wrong_op).is_empty());
    // Wrong b[6] must be skipped (guards the other filter `||`).
    let mut wrong_b6 = vec![0u8; 64];
    write_branch(&mut wrong_b6, 0, [0x100, 0x200]);
    wrong_b6[6] = 0x48;
    assert!(kernel_xor_branches(&wrong_b6).is_empty());
    // b[14] != 0x47 (with b[8..10]==b[..2]) steers to the else-if, which
    // does not match -> no branch. A `&& -> ||` at the if-head would push.
    let mut wrong_b14 = vec![0u8; 64];
    write_branch(&mut wrong_b14, 0, [0x100, 0x200]);
    wrong_b14[14] = 0;
    assert!(kernel_xor_branches(&wrong_b14).is_empty());

    // A valid target-34 branch is recognized (guards the match arm itself).
    let t34 = branch_t34([0x16900, 0x77300]);
    assert_eq!(kernel_xor_branches(&t34), vec![(0, [0x16900, 0x77300])]);
    // A target-34 shape whose body matches no known pattern is rejected; an
    // `== -> !=` in the pattern comparison would wrongly accept it.
    let mut t34_bad = t34.clone();
    t34_bad[16] ^= 0xff;
    assert!(kernel_xor_branches(&t34_bad).is_empty());

    // A valid WX1DM branch is recognized (guards the else-if `==` chain).
    let wx = branch_wx1dm([0x1000, 0x2000]);
    assert_eq!(kernel_xor_branches(&wx), vec![(0, [0x1000, 0x2000])]);
    // A WX1DM shape with a wrong middle or tail block is rejected; `&& -> ||`
    // or `== -> !=` in the else-if chain would wrongly accept it.
    let mut wx_mid = branch_wx1dm([0x1000, 0x2000]);
    wx_mid[7] ^= 0xff;
    assert!(kernel_xor_branches(&wx_mid).is_empty());
    let mut wx_tail = branch_wx1dm([0x1000, 0x2000]);
    wx_tail[20] ^= 0xff;
    assert!(kernel_xor_branches(&wx_tail).is_empty());
}

#[test]
fn comp_streams_guard_coverage() {
    // Valid stream compressed at level 6 recompresses exactly.
    let (base, s) = comp_streams(&comp_image(0x410000, &[(vec![0x5a; 512], 6)])).unwrap();
    assert_eq!(base, 0x410000);
    assert!(s[0].info.recompresses_exactly);
    // A level-9 stream does NOT recompress exactly: guards the `&&` in the
    // recompresses flag (a `||` mutant would force it always true).
    let (_, s9) = comp_streams(&comp_image(0x410000, &[(vec![0x5a; 512], 9)])).unwrap();
    assert!(!s9[0].info.recompresses_exactly);
    // An odd-length directory (with one otherwise-valid stream) is rejected;
    // a `|| -> &&` on the parity check would wrongly accept it.
    let mut odd = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
    odd[0x100c..0x1010].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    assert!(comp_streams(&odd).is_none());
    // A 2 MiB stream is within the 64 MiB cap; the `* -> +` mutants would
    // lower the cap to ~1 MiB / ~65 KiB and reject it.
    let big = comp_image(0x410000, &[(vec![0x5a; 2 * 1024 * 1024], 6)]);
    assert!(comp_streams(&big).is_some());
}

#[test]
fn rebuild_last_comp_cap_and_multi_stream_preservation() {
    // A 2 MiB replacement is accepted (< 64 MiB); the `* -> +` size-cap
    // mutants would reject it.
    let img = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
    assert!(rebuild_last_comp(&img, &vec![0xa5u8; 2 * 1024 * 1024]).is_some());

    // Rebuilding the last of two streams must leave the earlier stream
    // byte-identical: the `!= -> ==` mutants in the preservation check would
    // reject this valid rebuild.
    let two = comp_image(0x410000, &[(vec![0x11; 512], 6), (vec![0x22; 512], 6)]);
    let new_last = vec![0x33u8; 1024];
    let rebuilt = rebuild_last_comp(&two, &new_last).unwrap();
    let (_, rs) = comp_streams(&rebuilt).unwrap();
    assert_eq!(rs.len(), 2);
    assert_eq!(rs[0].expanded, vec![0x11u8; 512]);
    assert_eq!(rs[1].expanded, new_last);
}

#[test]
fn primitive_helpers_have_observable_behavior() {
    // sha produces a 64-char hex digest that depends on the input.
    assert_eq!(sha(b"abc").len(), 64);
    assert_ne!(sha(b"abc"), sha(b"abd"));
    // contains is a real substring search.
    assert!(contains(b"xxSAT yy", b"SAT "));
    assert!(!contains(b"abc", b"xyz"));
    // be32_sum_zero distinguishes zero-sum from non-zero-sum images.
    assert!(be32_sum_zero(&[0, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!be32_sum_zero(&[0, 0, 0, 1]));
    assert!(!be32_sum_zero(&[0, 0, 0])); // not a multiple of four
                                         // is_envelope requires the literal banner.
    assert!(is_envelope(BANNER));
    assert!(!is_envelope(b"not a Pioneer banner"));
    // uniform_ranges measures length by end-start: a short high-offset run
    // must not be reported (guards the `- with +` arithmetic mutant).
    let mut image = vec![0x11u8; 0x1000];
    image[0x400..0x40a].fill(0xff);
    assert!(uniform_ranges(&image, 256).is_empty());
    let mut long = vec![0x11u8; 0x1000];
    long[0x400..0x600].fill(0x00);
    assert_eq!(uniform_ranges(&long, 256).len(), 1);

    // transform_with_policy rejects a non-4-aligned data length, a non-4
    // aligned key length, and an empty key (each `|| -> &&` on that guard
    // would let one through).
    assert!(transform_with_policy(&[0u8; 5], &[0u8; 4], true, false, &[]).is_none());
    assert!(transform_with_policy(&[0u8; 4], &[0u8; 6], true, false, &[]).is_none());
    assert!(transform_with_policy(&[0u8; 4], &[], true, false, &[]).is_none());
}

fn plain_normal_env(image: &[u8]) -> Vec<u8> {
    let key = make_key(0x47d001, 0x10000);
    let mut env = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
    env.extend_from_slice(&key);
    env.extend_from_slice(&transform(image, &key, true).unwrap());
    env
}

#[test]
fn normal_layout_decodes_repacks_and_reports_unknown_word() {
    let mut image = normal_image(0x2000);
    image[16..20].copy_from_slice(&0xdead_beefu32.to_be_bytes());
    be32_fix(&mut image, 0x1f00);
    let env = plain_normal_env(&image);
    let decoded = decode_envelope(&env).unwrap();
    assert_eq!(decoded.info.layout, Layout::Normal);
    assert_eq!(decoded.image, image);
    // image.len() >= 20 -> unknown word is read (guards `>= 20` vs `< 20`).
    assert_eq!(decoded.info.unknown_word_0x10, Some(0xdead_beef));
    // Byte-exact repack: the trailing-suffix slice (`data.len() & !3`) must
    // stay empty for a 4-aligned envelope; dropping the `!` would append the
    // whole file.
    assert_eq!(decoded.repack(&decoded.image).unwrap(), env);
}

#[test]
fn decode_with_kernel_keeps_non_checksummed_normal_image() {
    let kernel = front_kernel();
    let dk = decode_envelope(
        &encode_kernel_envelope(&kernel, "PIONEER BDR-TEST", &KernelBuild::from_seed(1)).unwrap(),
    )
    .unwrap();
    let mut image = vec![0u8; 0x2000];
    image[..8].copy_from_slice(b"PIONEER ");
    image[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    image[0x400] = 1; // ensure a non-zero big-endian checksum
    assert!(!be32_sum_zero(&image));
    let key = make_key(0x47d001, 0x10000);
    let mut env = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
    env.extend_from_slice(&key);
    env.extend_from_slice(
        &transform_with_policy(&image, &key, true, false, &[0x100, 0x200]).unwrap(),
    );
    // layout is "normal" (not scaled), so the be32 checksum guard must NOT
    // apply here; a `== -> !=` on that layout check would reject it.
    let decoded = decode_envelope_with_kernel(&env, &dk).unwrap();
    assert_eq!(decoded.info.layout, Layout::Normal);
    assert_eq!(decoded.image, image);
}

fn small_comp_dump(declared_size: usize) -> Vec<u8> {
    let exp = vec![0x5au8; 64];
    let comp = zlib_at(&exp, 6);
    let stream_at = 0x1100usize;
    let mut dump = vec![0u8; 0x12000];
    dump[..8].copy_from_slice(b"PIONEER ");
    dump[20..24].copy_from_slice(&(declared_size as u32).to_be_bytes());
    dump[0x1000..0x1004].copy_from_slice(b"COMP");
    let start = stream_at as u32; // base 0
    let end = start + comp.len() as u32;
    dump[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
    dump[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
    dump[0x100c..0x1010].copy_from_slice(&[0xff; 4]); // directory terminator
    dump[stream_at..stream_at + 4].copy_from_slice(&(exp.len() as u32).to_be_bytes());
    dump[stream_at + 4..stream_at + 4 + comp.len()].copy_from_slice(&comp);
    dump
}

#[test]
fn carve_finds_an_image_ending_exactly_at_the_dump_end() {
    let mut dump = small_comp_dump(0x2000);
    dump.truncate(0x2000);
    assert_eq!(carve_live_main(&dump).len(), 1);
}

#[test]
fn rebuild_last_comp_refuses_a_stream_that_overlaps_the_directory() {
    // One stored-block stream at 0x100 whose payload covers the COMP
    // directory: it parses, but cannot be rebuilt (the directory word
    // rewritten lies inside the stream).
    let base = 0x40_0000u32;
    let len = 0x1000usize;
    let compressed_len = 2 + 5 + len + 4;
    let mut image = vec![0xffu8; 0x1200];
    image[..8].copy_from_slice(b"PIONEER ");
    image[20..24].copy_from_slice(&0x1200u32.to_be_bytes());
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    let start = base + 0x100;
    let end = start + compressed_len as u32;
    image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
    image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
    image[0x100..0x104].copy_from_slice(&(len as u32).to_be_bytes());
    image[0x104..0x106].copy_from_slice(&[0x78, 0x01]);
    image[0x106] = 0x01;
    image[0x107..0x109].copy_from_slice(&(len as u16).to_le_bytes());
    image[0x109..0x10b].copy_from_slice(&(!(len as u16)).to_le_bytes());
    let payload = image[0x10b..0x10b + len].to_vec();
    image[0x10b + len..0x10b + len + 4].copy_from_slice(&adler32(&payload).to_be_bytes());
    assert!(comp_streams(&image).is_some(), "fixture must parse");
    assert!(rebuild_last_comp(&image, &[0xa5; 16]).is_none());
}

#[test]
fn targets_requires_every_field_to_match_the_drive() {
    let mut inquiry = [b' '; crate::INQUIRY_LEN];
    inquiry[0] = 0x05;
    inquiry[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
    let mut vendor = [b' '; crate::IDENTITY_LEN];
    vendor[16..24].copy_from_slice(b"SAT 8A10");
    vendor[24..28].copy_from_slice(b"ID40");
    let drive = crate::Identity::parse(&inquiry, &vendor).unwrap();
    let header = |model: &str, hw: &str, tag: &str| HeaderInfo {
        id: format!("PIONEER {model}"),
        model: model.into(),
        revision: "1.00".into(),
        hardware_version: hw.into(),
        kernel_version: tag.into(),
        destination: tag.into(),
        generated_date: "00/00/00".into(),
        kernel_version2: "0000".into(),
        kind: Some(ComponentKind::Normal),
    };
    assert!(header("BDR-UD04", "SAT 8A10", "ID40").targets(&drive));
    assert!(!header("BDR-UD05", "SAT 8A10", "ID40").targets(&drive));
    assert!(!header("BDR-UD04", "SAT 8A11", "ID40").targets(&drive));
    assert!(!header("BDR-UD04", "SAT 8A10", "ID41").targets(&drive));
    // A header with missing fields never matches a drive with blank ones.
    let mut blank = vendor;
    blank[16..32].fill(b' ');
    let blank_drive = crate::Identity::parse(&inquiry, &blank).unwrap();
    assert!(!header("BDR-UD04", "", "").targets(&blank_drive));
}

#[test]
fn carve_size_boundary_exact() {
    // size exactly 0x2000 is accepted; `< -> ==` / `<=` would skip it.
    assert_eq!(carve_live_main(&small_comp_dump(0x2000)).len(), 1);
    // size not a multiple of 0x100 (but an otherwise-valid comp image) is
    // skipped; `|| -> &&` on the size guards would carve it.
    assert!(carve_live_main(&small_comp_dump(0x2050)).is_empty());
}

fn legacy_le_env(image: &[u8]) -> Vec<u8> {
    let mut env = vec![0u8; 0x10000];
    env[..0x200].copy_from_slice(&header_bytes("Kernel", "SAT 8A10", "GENERAL"));
    env[0x200..0x9000].fill(0xff);
    let key: Vec<u8> = (0..0x500u32)
        .map(|i| i.wrapping_mul(7).wrapping_add(1) as u8)
        .collect();
    env[0x9000..0x9500].copy_from_slice(&key);
    env[0x9500..0xb000].fill(0xff);
    env[0xb000..].copy_from_slice(&transform(image, &key, true).unwrap());
    env
}

fn valid_le_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x5000];
    image[4..0x1000].fill(0xff);
    image[0x1000..0x1008].copy_from_slice(b"PIONEER ");
    let mut tail = 0u32;
    let mut i = 0x1000;
    while i + 4 <= image.len() {
        tail = tail.wrapping_add(u32::from_le_bytes([
            image[i],
            image[i + 1],
            image[i + 2],
            image[i + 3],
        ]));
        i += 4;
    }
    image[..4].copy_from_slice(&0u32.wrapping_sub(tail).to_le_bytes());
    image
}

#[test]
fn legacy_le_region_and_pioneer_guards() {
    let valid = legacy_le_env(&valid_le_image());
    assert_eq!(
        decode_envelope(&valid).unwrap().info.layout,
        Layout::KernelLegacyLe
    );
    // A non-0xff byte in the reserved [0x200..0x9000] region disqualifies it.
    let mut dirty = valid.clone();
    dirty[0x300] = 0;
    assert!(decode_envelope(&dirty).is_none());
    // An image with no PIONEER marker (but a valid checksum and gap) is not
    // legacy-LE; a `|| -> &&` on that guard would accept it.
    let mut no_pioneer = vec![0u8; 0x5000];
    no_pioneer[4..0x1000].fill(0xff); // checksum word stays 0 -> sum is 0
    assert!(decode_envelope(&legacy_le_env(&no_pioneer)).is_none());
}

#[test]
fn repack_resized_normal_guard_isolation() {
    let valid = normal_image(0x2000);
    let tmpl = |image: Vec<u8>, ft: &str| DecodedEnvelope {
        info: EnvelopeInfo {
            model: "BDR".into(),
            revision: "1".into(),
            kind: ComponentKind::from_header(ft).unwrap(),
            hardware_version: String::new(),
            kernel_version: String::new(),
            layout: Layout::Normal,
            payload_offset: 0x10200,
            payload_size: image.len(),
            declared_size: Some(image.len()),
            unknown_word_0x10: None,
            uniform_ranges: vec![],
            receiver_xor_policy: None,
        },
        image,
        header: vec![0u8; HEADER_LEN],
        prefix: vec![0u8; 0x10200 - HEADER_LEN],
        suffix: vec![],
        key: make_key(0x123456, 0x10000),
        xor_exceptions: vec![],
        splices: vec![],
    };
    let base = tmpl(valid.clone(), "Normal");
    // Exact resize to length 0x2000 is valid (isolates `< 0x2000` vs `==`/`<=`).
    assert!(base.repack_resized_normal(&valid).is_some());
    // Wrong file type.
    assert!(tmpl(valid.clone(), "Kernel")
        .repack_resized_normal(&valid)
        .is_none());
    // Below the 0x2000 minimum.
    assert!(base.repack_resized_normal(&normal_image(0x1000)).is_none());
    // Not a multiple of 0x100.
    assert!(base.repack_resized_normal(&normal_image(0x2080)).is_none());
    // Missing PIONEER but matching the template's first 16 bytes.
    let mut x_img = valid.clone();
    x_img[0] = b'X';
    assert!(tmpl(x_img.clone(), "Normal")
        .repack_resized_normal(&x_img)
        .is_none());
    // First-16-bytes mismatch (still starts PIONEER).
    let mut diff16 = valid.clone();
    diff16[8] ^= 0xff;
    assert!(base.repack_resized_normal(&diff16).is_none());
    // COMP base must match: same base is accepted; `!= -> ==` would reject it.
    let comp_self = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
    let comp_big = comp_image(0x410000, &[(vec![0x5a; 4096], 6)]);
    assert!(tmpl(comp_self, "Normal")
        .repack_resized_normal(&comp_big)
        .is_some());
}

#[test]
fn normal_length_mismatch_reports_large_images() {
    // actual == 128 (>= 64) must report the mismatch; `< 64 -> > 64` skips it.
    let key = make_key(0x47d001, 0x10000);
    let mut env = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
    env.extend_from_slice(&key);
    let mut image = vec![0u8; 128];
    image[..8].copy_from_slice(b"PIONEER ");
    image[20..24].copy_from_slice(&256u32.to_be_bytes()); // declared != actual
    env.extend_from_slice(&transform(&image, &key, true).unwrap());
    assert_eq!(normal_length_mismatch(&env), Some((256, 128)));
}

#[test]
fn kernel_xor_policy_requires_kernel_layout() {
    let mut image = vec![0u8; 64];
    write_branch(&mut image, 0, [0x100, 0x200]);
    let env = DecodedEnvelope {
        image,
        info: EnvelopeInfo {
            model: "BDR".into(),
            revision: "1".into(),
            kind: ComponentKind::Kernel,
            hardware_version: String::new(),
            kernel_version: String::new(),
            layout: Layout::Plain, // not kernel-front/derived
            payload_offset: 0,
            payload_size: 64,
            declared_size: None,
            unknown_word_0x10: None,
            uniform_ranges: vec![],
            receiver_xor_policy: None,
        },
        header: vec![],
        prefix: vec![],
        suffix: vec![],
        key: vec![],
        xor_exceptions: vec![],
        splices: vec![],
    };
    // A `|| -> &&` on the layout guard would compute a policy from the branch.
    assert!(KernelXorPolicy::from_kernel(&env).is_none());
}

#[test]
fn build_header_field_and_id_guards_are_exact() {
    let info = |id: &str, model: &str, revision: &str| HeaderInfo {
        id: id.into(),
        model: model.into(),
        revision: revision.into(),
        hardware_version: "SAT 8A10".into(),
        kernel_version: "GENERAL".into(),
        destination: "GENERAL".into(),
        generated_date: "00/00/00".into(),
        kernel_version2: "0000".into(),
        kind: Some(ComponentKind::Normal),
    };
    let opq = |left: u8| HeaderOpaque {
        id_left_padding: left,
        prevalidation: [0; 0x10],
        validation: [0; 0x50],
        extension: [0; 0x30],
        filename: [0; 0x10],
    };
    // id's last token must equal the model.
    assert!(build_header(&info("PIONEER BDR-US04", "WRONG", "1.00"), &opq(0)).is_none());
    // A field value longer than its width (but all graphic) is rejected.
    assert!(build_header(&info("PIONEER BDR-US04", "BDR-US04", "123456"), &opq(0)).is_none());
    // id length + left == 24 is valid (isolates `> 24` vs `== 24` / `>= 24`).
    assert!(build_header(
        &info("PIONEER BD-RW   BDR-US04", "BDR-US04", "1.00"),
        &opq(0)
    )
    .is_some());
    // id length + left == 25 is rejected (isolates the id-graphic `||`).
    assert!(build_header(
        &info("PIONEER BD-RW    BDR-US04", "BDR-US04", "1.00"),
        &opq(0)
    )
    .is_none());
    // With left padding 2 and a 13-byte id (sum 15): valid, id written at
    // 0x62 so 0x60..0x62 stay spaces. This also fails if `+ left + id.len`
    // becomes `* left` (26 > 24 -> None -> unwrap panics) or the end index
    // `+ id.len()` becomes `- id.len()` (slice panic).
    let h = build_header(&info("PIONEER BD-RW", "BD-RW", "1.00"), &opq(2)).unwrap();
    assert_eq!(&h[0x60..0x62], b"  ");
    // With left 2 and a 24-byte id (sum 26 > 24): rejected. A `+ -> -`
    // mutant would compute 22 and wrongly accept it.
    assert!(build_header(
        &info("PIONEER BD-RW   BDR-US04", "BDR-US04", "1.00"),
        &opq(2)
    )
    .is_none());
}

#[test]
fn carve_rejects_misaligned_or_tiny_declared_sizes() {
    let mut dump = vec![0u8; 0x11000];
    dump[..8].copy_from_slice(b"PIONEER ");
    // Size not a multiple of 0x100.
    dump[20..24].copy_from_slice(&0x2050u32.to_be_bytes());
    assert!(carve_live_main(&dump).is_empty());
    // Size below the 0x2000 minimum.
    dump[20..24].copy_from_slice(&0x1000u32.to_be_bytes());
    assert!(carve_live_main(&dump).is_empty());
}

// ---- splice_tail ------------------------------------------------------

const TAIL_BASE: u32 = 0x40_0000;
const TAIL_OFF: usize = 0x2000;

fn raw_deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A single-stream COMP image: expanded-size field, zlib header byte, the
/// raw `deflate` bytes, then `trailer`; the directory end address points at
/// the trailer. Returns the image and the trailer offset.
fn tail_fixture(size: u32, hdr: u8, deflate: &[u8], trailer: [u8; 4]) -> (Vec<u8>, usize) {
    let end = TAIL_OFF + 6 + deflate.len();
    let mut image = vec![0xffu8; end + 4 + 0x20];
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    let dir = |image: &mut Vec<u8>, words: &[u32]| {
        for (i, w) in words.iter().enumerate() {
            image[0x1004 + i * 4..0x1008 + i * 4].copy_from_slice(&w.to_be_bytes());
        }
    };
    dir(
        &mut image,
        &[TAIL_BASE + TAIL_OFF as u32, TAIL_BASE + end as u32],
    );
    image[TAIL_OFF..TAIL_OFF + 4].copy_from_slice(&size.to_be_bytes());
    image[TAIL_OFF + 4] = hdr;
    image[TAIL_OFF + 5] = 0x01;
    image[TAIL_OFF + 6..end].copy_from_slice(deflate);
    image[end..end + 4].copy_from_slice(&trailer);
    (image, end)
}

fn padded(kept: &[u8], total: usize) -> Vec<u8> {
    let mut v = kept.to_vec();
    v.resize(total, 0xff);
    v
}

fn set_dir(image: &mut [u8], words: &[u32]) {
    image[0x1004..0x1100].fill(0xff);
    for (i, w) in words.iter().enumerate() {
        image[0x1004 + i * 4..0x1008 + i * 4].copy_from_slice(&w.to_be_bytes());
    }
}

#[test]
fn splice_tail_recomputes_a_cut_adler_trailer_exactly() {
    let data: Vec<u8> = (0..100u32).map(|i| (i * 7 % 13) as u8).collect();
    let deflate = raw_deflate(&data);
    let trailer = adler32(&data).to_be_bytes();
    let (full, e) = tail_fixture(100, 0x78, &deflate, trailer);
    let total = full.len();
    // 0..=3 trailer bytes carried: the rest is recomputed (including the
    // case where the whole trailer was lost).
    for carried in 0..4 {
        let out = splice_tail(&full[..e + carried], total).unwrap();
        assert_eq!(out, full, "carried {carried}");
    }
    // Same when the trailer ends exactly at the image end.
    let exact = &full[..e + 4];
    for carried in 0..4 {
        let out = splice_tail(&exact[..e + carried], e + 4).unwrap();
        assert_eq!(out, exact, "exact end, carried {carried}");
    }
    // A fully carried trailer needs nothing (and trailing erased bytes stay).
    let mut kept = full[..e + 8].to_vec();
    assert_eq!(splice_tail(&kept, total).unwrap(), full);
    // Carried trailer bytes that disagree with the stream stop the repair.
    kept = full[..e + 2].to_vec();
    kept[e] ^= 1;
    assert_eq!(splice_tail(&kept, total).unwrap(), padded(&kept, total));
    // Without a COMP marker the image is just padded.
    let mut no_comp = full[..e + 1].to_vec();
    no_comp[0x1000] = b'X';
    assert_eq!(
        splice_tail(&no_comp, total).unwrap(),
        padded(&no_comp, total)
    );
}

#[test]
fn splice_tail_refuses_streams_it_cannot_prove() {
    let data: Vec<u8> = (0..100u32).map(|i| (i * 7 % 13) as u8).collect();
    let deflate = raw_deflate(&data);
    let trailer = adler32(&data).to_be_bytes();
    let unchanged = |image: &[u8], keep: usize| {
        let total = image.len();
        assert_eq!(
            splice_tail(&image[..keep], total).unwrap(),
            padded(&image[..keep], total)
        );
    };

    // Stream trailer that ends at/after the image end can't be repaired.
    let (full, e) = tail_fixture(100, 0x78, &deflate, trailer);
    assert_eq!(
        splice_tail(&full[..e + 1], e + 3).unwrap(),
        padded(&full[..e + 1], e + 3)
    );

    // Trailer offset inside the stream header (end < start + 6).
    let (mut short, e) = tail_fixture(100, 0x78, &deflate, trailer);
    short[0x1008..0x100c].copy_from_slice(&(TAIL_BASE + TAIL_OFF as u32 + 3).to_be_bytes());
    unchanged(&short, TAIL_OFF + 6);
    let _ = e;

    // A deflate stream whose last bytes happen to be erased 0xff is still
    // cut: the end lies beyond the carried bytes, so nothing is repaired.
    let n = 20usize;
    let mut stored = vec![0x01, n as u8, 0, !(n as u8), 0xff];
    stored.extend(std::iter::repeat(0xff).take(n));
    let (full, e) = tail_fixture(n as u32, 0x78, &stored, adler32(&[0xff; 20]).to_be_bytes());
    unchanged(&full, e - 2);

    // Zlib header byte other than 0x78.
    let (full, e) = tail_fixture(100, 0x79, &deflate, trailer);
    unchanged(&full, e + 1);

    // Declared expanded size of zero (even for a genuinely empty stream).
    let (full, e) = tail_fixture(0, 0x78, &[0x03, 0x00], adler32(&[]).to_be_bytes());
    unchanged(&full, e + 1);

    // Deflate stream that never reaches its final block.
    let mut open = vec![0x00, n as u8, 0, !(n as u8), 0xff];
    let body: Vec<u8> = (0..n as u8).collect();
    open.extend_from_slice(&body);
    let (full, e) = tail_fixture(n as u32, 0x78, &open, adler32(&body).to_be_bytes());
    unchanged(&full, e + 1);

    // Declared size larger than what the stream expands to.
    let (full, e) = tail_fixture(101, 0x78, &deflate, trailer);
    unchanged(&full, e + 1);

    // Bytes after the end of the deflate stream within the directory span.
    let mut junk = deflate.clone();
    junk.extend_from_slice(&[1, 2, 3]);
    let (full, e) = tail_fixture(100, 0x78, &junk, trailer);
    unchanged(&full, e + 1);

    // Odd-sized directory: not start/end pairs, left alone.
    let (mut full, e) = tail_fixture(100, 0x78, &deflate, trailer);
    let start = TAIL_BASE + TAIL_OFF as u32;
    set_dir(&mut full, &[start, start, TAIL_BASE + e as u32]);
    unchanged(&full, e + 1);

    // Empty directory: nothing to repair, and no panic.
    let (mut full, e) = tail_fixture(100, 0x78, &deflate, trailer);
    set_dir(&mut full, &[]);
    unchanged(&full, e + 1);
}

#[test]
fn splice_tail_expanded_size_cap_is_inclusive() {
    let max = crate::comp::MAX_EXPANDED;
    let zeros = vec![0u8; max + 1];
    let at_cap = raw_deflate(&zeros[..max]);
    let trailer = adler32(&zeros[..max]).to_be_bytes();
    let (full, e) = tail_fixture(max as u32, 0x78, &at_cap, trailer);
    assert_eq!(splice_tail(&full[..e + 1], full.len()).unwrap(), full);

    let over = raw_deflate(&zeros);
    let (full, e) = tail_fixture(max as u32 + 1, 0x78, &over, [0; 4]);
    assert_eq!(
        splice_tail(&full[..e + 1], full.len()).unwrap(),
        padded(&full[..e + 1], full.len())
    );
}

// ---- comp_valid_except_truncated_last ---------------------------------

fn comp_n(n: usize) -> (Vec<u8>, u32) {
    // Distinct sizes so no other base also validates the trimmed directory.
    let streams: Vec<(Vec<u8>, u32)> = (0..n)
        .map(|i| {
            let len = 200 + 77 * i;
            ((0..len).map(|j| (j * 31 + i * 7) as u8 ^ 0x5a).collect(), 6)
        })
        .collect();
    (comp_image(0x410000, &streams), 0x410000)
}

fn with_last_end(mut image: Vec<u8>, count: usize, end: u32) -> Vec<u8> {
    image[0x1004 + (count - 1) * 4..0x1008 + (count - 1) * 4].copy_from_slice(&end.to_be_bytes());
    image
}

#[test]
fn comp_valid_except_truncated_last_needs_a_last_end_inside_the_lost_tail() {
    for n in [2usize, 3] {
        let (img, base) = comp_n(n);
        let len = img.len();
        let count = 2 * n;
        let at = |end_off: usize| with_last_end(img.clone(), count, base + end_off as u32);
        let kept = len - 0x40;
        // End after the carried bytes and inside the image: accepted.
        assert!(comp_valid_except_truncated_last(&at(kept + 1), kept), "{n}");
        assert!(comp_valid_except_truncated_last(&at(len - 1), kept), "{n}");
        // End exactly at the carried length: it is not in the lost tail.
        assert!(!comp_valid_except_truncated_last(&at(kept), kept));
        assert!(!comp_valid_except_truncated_last(&at(kept - 5), kept));
        // End at or beyond the image length: not inside the image.
        assert!(!comp_valid_except_truncated_last(&at(len), kept));
        assert!(!comp_valid_except_truncated_last(&at(len + 5), kept));
        // The earlier streams must still be a valid unique set.
        let mut broken = at(kept + 1);
        broken[TAIL_OFF + 4] = 0;
        assert!(!comp_valid_except_truncated_last(&broken, kept));
    }
    // A single stream (two directory words) is never enough, nor is an
    // odd-sized directory.
    let (img, base) = comp_n(1);
    let len = img.len();
    assert!(!comp_valid_except_truncated_last(
        &with_last_end(img.clone(), 2, base + len as u32 - 1),
        len - 0x40
    ));
    let (mut img, base) = comp_n(2);
    let len = img.len();
    let end = (base + len as u32 - 1).to_be_bytes();
    img[0x1014..0x1018].copy_from_slice(&end);
    assert!(!comp_valid_except_truncated_last(&img, len - 0x40));
    // No directory window at all.
    assert!(!comp_valid_except_truncated_last(&img[..0x1000], 0));
}

// ---- comp_streams / rebuild_last_comp ---------------------------------

#[test]
fn comp_streams_accepts_a_stream_at_the_image_base() {
    let exp = vec![0x5au8; 512];
    let comp = zlib_at(&exp, 6);
    let mut image = vec![0xffu8; 0x2000];
    image[..4].copy_from_slice(&(exp.len() as u32).to_be_bytes());
    image[4..4 + comp.len()].copy_from_slice(&comp);
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    set_dir(&mut image, &[0x410000, 0x410000 + comp.len() as u32]);
    let (base, streams) = comp_streams(&image).unwrap();
    assert_eq!(base, 0x410000);
    assert_eq!(streams[0].info.image_offset, 0);
    assert_eq!(streams[0].expanded, exp);
}

#[test]
fn comp_streams_accepts_streams_listed_out_of_address_order() {
    let mut image = comp_image(0x410000, &[(vec![0x11; 300], 6), (vec![0x22; 300], 6)]);
    let d: Vec<u8> = image[0x1004..0x1014].to_vec();
    // swap the two (start, end) pairs
    image[0x1004..0x100c].copy_from_slice(&d[8..16]);
    image[0x100c..0x1014].copy_from_slice(&d[..8]);
    let (base, streams) = comp_streams(&image).unwrap();
    assert_eq!(base, 0x410000);
    assert_eq!(streams[0].info.image_offset, 0x3000);
    assert_eq!(streams[1].info.image_offset, 0x2000);
}

#[test]
fn comp_streams_rejects_end_before_start_even_below_the_base() {
    let mut image = comp_image(0x410000, &[(vec![0x11; 300], 6), (vec![0x22; 300], 6)]);
    // Second pair: valid start, end address far below any image base.
    image[0x100c..0x1010].copy_from_slice(&0x412000u32.to_be_bytes());
    image[0x1010..0x1014].copy_from_slice(&0x1000u32.to_be_bytes());
    assert!(comp_streams(&image).is_none());
}

#[test]
fn comp_streams_rejects_streams_that_do_not_inflate_exactly() {
    let good = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
    let (_, s) = comp_streams(&good).unwrap();
    let off = s[0].info.image_offset;
    let end = off + 4 + s[0].info.compressed_size;

    // Declared size zero, even for a genuinely empty zlib stream.
    let empty = zlib_at(&[], 6);
    let mut zero = vec![0xffu8; 0x2000];
    zero[0x1000..0x1004].copy_from_slice(b"COMP");
    zero[0x2000 - 0x2000..4].copy_from_slice(&0u32.to_be_bytes());
    zero[4..4 + empty.len()].copy_from_slice(&empty);
    set_dir(&mut zero, &[0x410000, 0x410000 + empty.len() as u32]);
    assert!(comp_streams(&zero).is_none());

    // Corrupt Adler-32 trailer: the decoder errors after the data.
    let mut bad = good.clone();
    bad[end - 1] ^= 0x55;
    assert!(comp_streams(&bad).is_none());

    // Declared size larger than the real expansion.
    let mut bigger = good.clone();
    bigger[off..off + 4].copy_from_slice(&513u32.to_be_bytes());
    assert!(comp_streams(&bigger).is_none());

    // Declared size smaller than the real expansion.
    let mut smaller = good.clone();
    smaller[off..off + 4].copy_from_slice(&511u32.to_be_bytes());
    assert!(comp_streams(&smaller).is_none());

    // Extra bytes inside the directory span after the zlib stream.
    let mut junk = good.clone();
    let e = s[0].info.address_end + 3;
    junk[0x1008..0x100c].copy_from_slice(&e.to_be_bytes());
    junk[end..end + 3].copy_from_slice(&[1, 2, 3]);
    assert!(comp_streams(&junk).is_none());
}

#[test]
fn comp_and_rebuild_expanded_size_cap_is_inclusive() {
    let max = crate::comp::MAX_EXPANDED;
    let at_cap = comp_image(0x410000, &[(vec![0u8; max], 6)]);
    let (_, s) = comp_streams(&at_cap).unwrap();
    assert_eq!(s[0].info.expanded_size, max);
    // Rebuilding to exactly the cap is allowed; one byte more is not.
    let rebuilt = rebuild_last_comp(&at_cap, &vec![0xa5u8; max]).unwrap();
    assert!(comp_streams(&rebuilt).is_some());
    assert!(rebuild_last_comp(&at_cap, &vec![0xa5u8; max + 1]).is_none());
    assert!(rebuild_last_comp(&at_cap, &[]).is_none());

    let over = comp_image(0x410000, &[(vec![0u8; max + 1], 6)]);
    assert!(comp_streams(&over).is_none());
}

// ---- small helpers ----------------------------------------------------

#[test]
fn recover_seed_needs_eight_bytes_of_lcg_output() {
    let key = make_key(0x123456, 16);
    assert_eq!(recover_seed(&key[..8]), Some(0x123456));
    assert_eq!(recover_seed(&key[..7]), None);
    assert_eq!(recover_seed(&key[..4]), None);
    assert_eq!(recover_seed(&[]), None);
}

#[test]
fn layout_names_are_stable_and_displayed() {
    let all = [
        (Layout::Plain, "plain"),
        (Layout::TransformedPlane, "transformed-plane"),
        (Layout::Normal, "normal"),
        (Layout::NormalReverse, "normal-reverse"),
        (Layout::NormalScaledKey, "normal-scaled-key"),
        (Layout::KernelFront, "kernel-front"),
        (Layout::KernelDerived, "kernel-derived"),
        (Layout::KernelLegacyLe, "kernel-legacy-le"),
    ];
    for (layout, name) in all {
        assert_eq!(layout.as_str(), name);
        assert_eq!(format!("{layout}"), name);
    }
}

// ---- decode_envelope_impl guards --------------------------------------

#[test]
fn decode_rejects_truncated_inputs_without_panicking() {
    assert!(decode_envelope(&[]).is_none());
    assert!(decode_envelope(BANNER).is_none());
    assert!(decode_envelope(&BANNER[..10]).is_none());
    // Normal envelope shorter than key + 64 payload bytes.
    let mut short = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
    short.resize(0x10200 + 10, 0);
    assert!(decode_envelope(&short).is_none());
    short.resize(0x20200 + 10, 0);
    assert!(decode_envelope(&short).is_none());
}

#[test]
fn scaled_key_geometry_applies_only_to_normal_envelopes() {
    // A Kernel-typed envelope whose length fits the 17-unit geometry and
    // whose "payload" decodes (zero key) to a Pioneer prefix is not a Normal.
    let mut env = header_bytes("Kernel", "SAT 8A10", "GENERAL").to_vec();
    env.extend_from_slice(&[0u8; 0x200]);
    let mut payload = vec![0u8; 0x2000];
    payload[..8].copy_from_slice(b"PIONEER ");
    env.extend_from_slice(&payload);
    assert_eq!(env.len(), 0x200 + 17 * 0x200);
    assert!(decode_envelope(&env).is_none());
    // The same bytes under a Normal header do decode as scaled-key.
    env[..0x200].copy_from_slice(&header_bytes("Normal", "SAT 8A10", "GENERAL"));
    let decoded = decode_envelope(&env).unwrap();
    assert_eq!(decoded.info.layout, Layout::NormalScaledKey);
}

// ---- transformed Plane guards -----------------------------------------

#[test]
fn transformed_plane_layout_guards_are_each_necessary() {
    let mut plain = vec![0xffu8; 0x10010];
    let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-217\r\nRevision Level : 1.07\r\nFile Type : Plane\r\n";
    plain[..banner.len()].copy_from_slice(banner);
    plain[0x8000..0x8004].copy_from_slice(&[0x00, 0x55, 0x09, 0xfd]);
    plain[0x10000..0x10010].copy_from_slice(b"PIONEER  DVR-117");
    let mut env = plain[..PLANE_XOR_OFFSET].to_vec();
    env.extend(plane_lcg_xor(&plain[PLANE_XOR_OFFSET..]));
    let (layout, off, end, key, suffix) =
        transformed_plane_layout(&env, ComponentKind::Plane).unwrap();
    assert_eq!(layout, Layout::TransformedPlane);
    assert_eq!((off, end), (HEADER_LEN, env.len()));
    assert!(key.is_empty() && suffix.is_empty());
    // Only Plane envelopes qualify.
    assert!(transformed_plane_layout(&env, ComponentKind::Normal).is_none());
    // A body too short for the whitened region is rejected, not sliced.
    assert!(transformed_plane_layout(&[0u8; 0x100], ComponentKind::Plane).is_none());
    assert!(transformed_plane_layout(&[0u8; 0x200], ComponentKind::Plane).is_none());
    // Whitening needs a word-aligned body.
    let mut ragged = env.clone();
    ragged.push(0xaa);
    assert!(transformed_plane_layout(&ragged, ComponentKind::Plane).is_none());
    // A bare direct-copy Plane is the Plain layout, not a transformed one.
    assert!(transformed_plane_layout(&plain, ComponentKind::Plane).is_none());
}

// ---- DecodedEnvelope delegates ----------------------------------------

fn drive(model: &str, platform: &str, tag: &str) -> crate::Identity {
    let mut inquiry = [b' '; crate::INQUIRY_LEN];
    inquiry[0] = 0x05;
    let product = format!("BD-RW   {model}");
    inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
    let mut vendor = [b' '; crate::IDENTITY_LEN];
    vendor[16..16 + platform.len()].copy_from_slice(platform.as_bytes());
    vendor[24..24 + tag.len()].copy_from_slice(tag.as_bytes());
    crate::Identity::parse(&inquiry, &vendor).unwrap()
}

fn decoded_with(hardware: &str, kernel_tag: &str, image: &[u8]) -> DecodedEnvelope {
    let info = HeaderInfo {
        id: "PIONEER BDR-US04".into(),
        model: "BDR-US04".into(),
        revision: "1.00".into(),
        hardware_version: hardware.into(),
        kernel_version: kernel_tag.into(),
        destination: "GENERAL".into(),
        generated_date: "00/00/00".into(),
        kernel_version2: "0000".into(),
        kind: Some(ComponentKind::Normal),
    };
    let opaque = HeaderOpaque {
        id_left_padding: 0,
        prevalidation: [0; 0x10],
        validation: [0; 0x50],
        extension: [0; 0x30],
        filename: [0; 0x10],
    };
    let mut env = build_header(&info, &opaque).unwrap().to_vec();
    let key = make_key(0x47d001, 0x10000);
    env.extend_from_slice(&key);
    env.extend_from_slice(&transform(image, &key, true).unwrap());
    decode_envelope(&env).unwrap()
}

#[test]
fn decoded_envelope_targets_and_role_follow_the_header() {
    let image = normal_image(0x2000);
    let d = decoded_with("SAT 8A10", "ID40", &image);
    assert!(d.targets(&drive("BDR-US04", "SAT 8A10", "ID40")));
    assert!(!d.targets(&drive("BDR-US05", "SAT 8A10", "ID40")));
    assert!(!d.targets(&drive("BDR-US04", "SAT 8A11", "ID40")));
    assert!(!d.targets(&drive("BDR-US04", "SAT 8A10", "ID41")));
    // Blank hardware / Kernel tag never match a drive reporting blanks.
    let blank = decoded_with("", "ID40", &image);
    assert!(!blank.targets(&drive("BDR-US04", "", "ID40")));
    let blank = decoded_with("SAT 8A10", "", &image);
    assert!(!blank.targets(&drive("BDR-US04", "SAT 8A10", "")));
    assert_eq!(d.role(), Some(crate::Role::Normal));
}

#[test]
fn decoded_envelope_image_queries_delegate_to_the_decoded_image() {
    // Normal body (> a Kernel) with a Kernel call, a register write that
    // gives a hardware family, and the UHD signature.
    let mut image = vec![0u8; 0x20000];
    for (i, b) in image.iter_mut().enumerate() {
        *b = if i & 1 == 0 { 0x0A } else { 0x01 };
    }
    image[..8].copy_from_slice(b"PIONEER ");
    let n = image.len() as u32;
    image[20..24].copy_from_slice(&n.to_be_bytes());
    image[0x3000..0x3004].copy_from_slice(&[0x5E, 0x40, 0x01, 0x02]);
    image[0x4000..0x4006].copy_from_slice(&[0xF0, 0x12, 0x6A, 0x80, 0xE4, 0x36]);
    let d = decoded_with("SAT 8A10", "ID40", &image);
    assert_eq!(d.image, image);
    let abi = d.required_abi().unwrap();
    assert_eq!(abi.entries(), &[0x40_0102]);
    assert_eq!(Some(abi), crate::image::required_abi(&image));
    let family = d.family().unwrap();
    assert_eq!(Some(family), crate::image::family(&image));
    assert!(!d.is_uhd());
    assert!(d.provided_abi().is_none());

    let mut uhd = image.clone();
    uhd[0x5000..0x5018].copy_from_slice(&[
        0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00, 0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0, 0x00,
        0xC4, 0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
    ]);
    assert!(decoded_with("SAT 8A10", "ID40", &uhd).is_uhd());

    // A Kernel provides an ABI; a Normal does not.
    let kernel = decode_envelope(
        &encode_kernel_envelope(
            &front_kernel(),
            "PIONEER BDR-TEST",
            &KernelBuild::from_seed(1),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(kernel.role(), Some(crate::Role::Kernel));
    assert_eq!(
        kernel.provided_abi(),
        crate::image::provided_abi(&front_kernel())
    );
    assert!(kernel.provided_abi().is_some());
    assert!(kernel.required_abi().is_none());
}

#[test]
fn spliced_normal_decodes_with_kernel_policy_in_the_envelope_direction() {
    use super::splice_tests::{envelope, image};
    let img = image();
    let env = envelope(&img, &[0xfe00, 0x2fe00, 0x3fe00]);
    let dk = decode_envelope(
        &encode_kernel_envelope(
            &front_kernel(),
            "PIONEER BDR-TEST",
            &KernelBuild::from_seed(1),
        )
        .unwrap(),
    )
    .unwrap();
    let d = decode_envelope_with_kernel(&env, &dk).unwrap();
    assert_eq!(d.info.layout, Layout::Normal);
    assert_eq!(d.spliced_blocks().len(), 3);
    assert_eq!(
        d.receiver_xor_exceptions(),
        Some([0x100u32, 0x200].as_slice())
    );
    // The envelope was produced without exceptions, so exactly the two
    // exception words decode differently; everything else is the image.
    for (i, (got, want)) in d.image.chunks(4).zip(img.chunks(4)).enumerate() {
        if i * 4 == 0x100 || i * 4 == 0x200 {
            assert_ne!(got, want, "word {i:#x}");
        } else {
            assert_eq!(got, want, "word {i:#x}");
        }
    }
    assert_eq!(d.repack(&d.image).unwrap(), env);
}

#[test]
fn rebuild_last_comp_rounds_up_to_the_next_0x100_for_every_residue() {
    let img = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
    let mut residues = std::collections::BTreeSet::new();
    for len in 1..600usize {
        let body: Vec<u8> = (0..len).map(|i| (i * 131 % 251) as u8).collect();
        let rebuilt = rebuild_last_comp(&img, &body).unwrap();
        assert_eq!(rebuilt.len() % 0x100, 0, "len {len}");
        let (_, streams) = comp_streams(&rebuilt).unwrap();
        let last = streams.last().unwrap();
        let used = last.info.image_offset + 4 + last.info.compressed_size;
        assert!(rebuilt.len() >= used && rebuilt.len() - used < 0x100);
        assert_eq!(
            u32::from_be_bytes(rebuilt[20..24].try_into().unwrap()) as usize,
            rebuilt.len()
        );
        residues.insert(used % 0x100);
    }
    assert!(residues.contains(&1) && residues.contains(&0));
}
