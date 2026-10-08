use super::*;

#[test]
fn scaled_receiver_geometry_matches_oem_when_configured() {
    let Ok(path) = std::env::var("PIONEER_SCALED_KERNEL_FIXTURE") else {
        return;
    };
    let normal_path = std::env::var("PIONEER_SCALED_NORMAL_FIXTURE").unwrap();
    let kernel = decode_envelope(&std::fs::read(path).unwrap()).unwrap();
    let normal_bytes = std::fs::read(normal_path).unwrap();
    let normal = decode_envelope_with_kernel(&normal_bytes, &kernel).unwrap();
    let geometry = scaled_normal_geometry_from_kernel(&kernel.image).unwrap();
    assert_eq!(geometry.image_len, normal.image.len());
    assert_eq!(geometry.envelope_len, normal_bytes.len());
    assert_eq!(geometry.key_len, normal.image.len() / 16);
    assert!(normal_authentication_valid(&normal_bytes, &kernel.image));
    let mut damaged = normal_bytes.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    assert!(!normal_authentication_valid(&damaged, &kernel.image));
    let h = super::super::header_info(&normal_bytes).unwrap();
    let mut private = [0; 20];
    private[19] = 5;
    let signer = SigningKey::from_bytes(private).unwrap();
    let rebuilt = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel.image,
            normal_image: &normal.image,
            envelope_id: &h.id,
            normal_revision: &h.revision,
            normal_date: &h.generated_date,
            kernel: KernelBuild::from_seed(1),
            normal_key_seed: 0x47d001,
        },
        NormalSignature::Sign(&signer),
    );
    let rebuilt = rebuilt.unwrap();
    validate_encrypted_pair(&rebuilt, &kernel.image, &normal.image).unwrap();
    if !h.destination.starts_with("ID") {
        assert!(rebuilt.normal[0x1f0..].starts_with(b"NORMAL."));
        assert_eq!(
            super::super::header_info(&rebuilt.normal)
                .unwrap()
                .destination,
            h.destination
        );
    }
    assert_eq!(
        kernel_layout_from_image(&kernel.image),
        Some(Layout::KernelFront)
    );

    // An inconsistent decoder image length cannot become an inferred read
    // size; duplicate valid call sites must also fail as ambiguous.
    let mut changed = kernel.image.clone();
    let decoder = legacy_decoder_target(&changed).unwrap();
    let at = changed
        .windows(32)
        .position(|w| w[..2] == [0x7a, 0x21] && w[28..] == decoder)
        .unwrap();
    changed[at + 21] ^= 1;
    assert_eq!(scaled_normal_geometry_from_kernel(&changed), None);
    let mut ambiguous = kernel.image.clone();
    ambiguous.extend_from_slice(&kernel.image[at..at + 32]);
    assert_eq!(scaled_normal_geometry_from_kernel(&ambiguous), None);
}

#[test]
fn live_ud04_images_make_independent_encrypted_pair_when_configured() {
    let Ok(path) = std::env::var("PIONEER_LIVE_DUMP_FIXTURE") else {
        return;
    };
    let dump = std::fs::read(path).unwrap();
    assert_eq!(dump.len(), 0x600000);
    let kernel = &dump[0x400000..0x410000];
    let normal = &dump[0x410000..0x5d7500];
    let mut private = [0u8; 20];
    private[19] = 5;
    let signer = SigningKey::from_bytes(private).unwrap();
    let input = BuildInputs {
        kernel_image: kernel,
        normal_image: normal,
        envelope_id: "PIONEER BD-RW   BDR-UD04",
        normal_revision: "1.14",
        normal_date: "20/06/15",
        kernel: KernelBuild::from_seed(0x123456),
        normal_key_seed: 0x47d001,
    };
    let pair = encode_encrypted_pair(&input, NormalSignature::Sign(&signer)).unwrap();
    assert_eq!(
        decode_envelope(&pair.kernel).unwrap().encoding_seed(),
        Some(0x123456)
    );
    assert_eq!(
        decode_envelope(&pair.normal).unwrap().encoding_seed(),
        Some(input.normal_key_seed)
    );
    validate_encrypted_pair(&pair, kernel, normal).unwrap();
    assert_eq!(pair.kernel.len(), 0x11200);
    assert_eq!(pair.normal.len(), 0x1d7700);
    let mut tampered = pair;
    tampered.normal[0x1d7600] ^= 1;
    assert!(validate_encrypted_pair(&tampered, kernel, normal).is_err());

    assert_eq!(kernel_layout_from_image(kernel), Some(Layout::KernelFront));
}

// ---- Synthetic-fixture coverage for the recognizers and guards ----

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

fn front_kernel_with(branch: [u32; 2]) -> Vec<u8> {
    let mut k = vec![0u8; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
    k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
    k[0x1010..0x1014].copy_from_slice(b"0000");
    k[0x40] = 0xae;
    k[0x41] = 0xfe;
    k[0x46] = 0xae;
    k[0x47] = 0xf0;
    write_branch(&mut k, 0x100, branch);
    be32_fix(&mut k, 0xff00);
    k
}

fn front_kernel() -> Vec<u8> {
    front_kernel_with([0x100, 0x200])
}

fn normal_image(len: usize) -> Vec<u8> {
    let mut n = vec![0u8; len];
    n[..8].copy_from_slice(b"PIONEER ");
    n[20..24].copy_from_slice(&(len as u32).to_be_bytes());
    be32_fix(&mut n, len - 0x100);
    n
}

const DECODER: [u8; 4] = [0x5e, 0x40, 0x01, 0x00];

fn with_legacy_site(k: &mut [u8], at: usize, decoder: [u8; 4]) {
    const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
    k[at - 6..at].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
    k[at..at + 12].copy_from_slice(&ARGS);
    k[at + 12..at + 16].copy_from_slice(&decoder);
}

#[allow(clippy::too_many_arguments)]
fn scaled_window(k: &mut [u8], at: usize, env: u32, keyword: u32, img: u32, decoder: [u8; 4]) {
    k[at] = 0x7a;
    k[at + 1] = 0x21;
    k[at + 2..at + 6].copy_from_slice(&env.to_be_bytes());
    k[at + 6] = 0x58;
    k[at + 7] = 0x60;
    k[at + 10] = 0x7a;
    k[at + 11] = 0;
    k[at + 12..at + 16].copy_from_slice(&keyword.to_be_bytes());
    k[at + 16] = 0x7a;
    k[at + 17] = 1;
    k[at + 18..at + 22].copy_from_slice(&img.to_be_bytes());
    k[at + 22..at + 28].copy_from_slice(&[0x7a, 2, 0, 1, 4, 0]);
    k[at + 28..at + 32].copy_from_slice(&decoder);
}

fn base_inputs<'a>(kernel: &'a [u8], normal: &'a [u8]) -> BuildInputs<'a> {
    BuildInputs {
        kernel_image: kernel,
        normal_image: normal,
        envelope_id: "PIONEER BDR-TEST",
        normal_revision: "1.00",
        normal_date: "00/00/00",
        kernel: KernelBuild::from_seed(0x123456),
        normal_key_seed: 0x47d001,
    }
}

fn a_signer() -> SigningKey {
    let mut private = [0u8; 20];
    private[19] = 5;
    SigningKey::from_bytes(private).unwrap()
}

#[test]
fn legacy_decoder_target_requires_unique_site_and_in_range_target() {
    let mut k = vec![0u8; 0x2000];
    with_legacy_site(&mut k, 0x300, DECODER);
    assert_eq!(legacy_decoder_target(&k), Some(DECODER));

    // Target resolving outside the image is rejected.
    let mut out = vec![0u8; 0x2000];
    with_legacy_site(&mut out, 0x300, [0x5e, 0x60, 0x00, 0x00]);
    assert!(legacy_decoder_target(&out).is_none());

    // Two valid call sites are ambiguous.
    let mut amb = vec![0u8; 0x2000];
    with_legacy_site(&mut amb, 0x300, DECODER);
    with_legacy_site(&mut amb, 0x800, DECODER);
    assert!(legacy_decoder_target(&amb).is_none());

    // The argument block without any recognized length prelude is not a site.
    let mut nolen = vec![0u8; 0x2000];
    nolen[0x300..0x30c].copy_from_slice(&[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0]);
    nolen[0x30c..0x310].copy_from_slice(&DECODER);
    assert!(legacy_decoder_target(&nolen).is_none());
}

#[test]
fn scaled_geometry_enforces_the_16_to_1_relationship() {
    let mut k = vec![0u8; 0x2000];
    with_legacy_site(&mut k, 0x300, DECODER);
    scaled_window(&mut k, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
    let g = scaled_normal_geometry_from_kernel(&k).unwrap();
    assert_eq!(
        (g.image_len, g.key_len, g.envelope_len),
        (0x2000, 0x200, 0x2400)
    );

    // key_len * 16 must equal image_len.
    let mut bad = vec![0u8; 0x2000];
    with_legacy_site(&mut bad, 0x300, DECODER);
    scaled_window(&mut bad, 0x400, 0x2500, 0x10700, 0x2000, DECODER);
    assert!(scaled_normal_geometry_from_kernel(&bad).is_none());

    // 0x200 + key_len + image_len must equal envelope_len.
    let mut bad_env = vec![0u8; 0x2000];
    with_legacy_site(&mut bad_env, 0x300, DECODER);
    scaled_window(&mut bad_env, 0x400, 0x2401, 0x10600, 0x2000, DECODER);
    assert!(scaled_normal_geometry_from_kernel(&bad_env).is_none());

    // image_len below the 0x2000 minimum is rejected.
    let mut small = vec![0u8; 0x2000];
    with_legacy_site(&mut small, 0x300, DECODER);
    scaled_window(&mut small, 0x400, 0x1300, 0x10500, 0x1000, DECODER);
    assert!(scaled_normal_geometry_from_kernel(&small).is_none());

    // The window's decoder word must match the resolved call target.
    let mut mismatch = vec![0u8; 0x2000];
    with_legacy_site(&mut mismatch, 0x300, DECODER);
    scaled_window(
        &mut mismatch,
        0x400,
        0x2400,
        0x10600,
        0x2000,
        [0x5e, 0x40, 0x02, 0x00],
    );
    assert!(scaled_normal_geometry_from_kernel(&mismatch).is_none());

    // Two identical windows are ambiguous.
    let mut dup = vec![0u8; 0x2000];
    with_legacy_site(&mut dup, 0x300, DECODER);
    scaled_window(&mut dup, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
    scaled_window(&mut dup, 0x800, 0x2400, 0x10600, 0x2000, DECODER);
    assert!(scaled_normal_geometry_from_kernel(&dup).is_none());
}

#[test]
fn legacy_normal_authentication_distinguishes_unsigned_and_signed() {
    const UNSIGNED_ARGS: [u8; 34] = [
        0x7a, 0x31, 0, 1, 2, 0, 0x01, 0, 0x69, 0xf4, 0x0f, 0xf0, 0x79, 0x10, 0, 8, 0x01, 0, 0x6f,
        0xf0, 0, 4, 0x7a, 0, 0, 2, 4, 0, 0x7a, 2, 0, 1, 4, 0,
    ];
    let mut unsigned = vec![0u8; 0x2000];
    with_legacy_site(&mut unsigned, 0x300, DECODER);
    unsigned[0x400..0x422].copy_from_slice(&UNSIGNED_ARGS);
    unsigned[0x422..0x426].copy_from_slice(&DECODER);
    assert_eq!(
        normal_authentication_from_kernel(&unsigned),
        Some(NormalAuthentication::Unsigned)
    );

    let mut signed = vec![0u8; 0x2000];
    with_legacy_site(&mut signed, 0x300, DECODER);
    signed[0x400..0x40e].copy_from_slice(&[
        0x7a, 0, 0, 0xa1, 4, 0, 0x7a, 2, 0, 0xa1, 3, 0x70, 0x5e, 0x40,
    ]);
    assert_eq!(
        normal_authentication_from_kernel(&signed),
        Some(NormalAuthentication::KeyAndCiphertext)
    );

    // Neither marker present -> ambiguous -> None.
    let mut neither = vec![0u8; 0x2000];
    with_legacy_site(&mut neither, 0x300, DECODER);
    assert_eq!(normal_authentication_from_kernel(&neither), None);

    // Unsigned validity is the all-zero header signature region.
    let mut normal = vec![0u8; 0x2000];
    assert!(normal_authentication_valid(&normal, &unsigned));
    normal[0x180] = 1;
    assert!(!normal_authentication_valid(&normal, &unsigned));
}

#[test]
fn destination_code_maps_general_and_id_tags_only() {
    assert_eq!(destination_code("GENERAL"), Some("00"));
    assert_eq!(destination_code("ID72"), Some("72"));
    assert_eq!(destination_code("IDAB"), Some("AB"));
    assert_eq!(destination_code("ID7"), None);
    assert_eq!(destination_code("ID7!"), None);
    assert_eq!(destination_code("OTHER"), None);
}

#[test]
fn filename_rejects_overlong_or_non_ascii() {
    assert_eq!(&filename("S8A10001.114").unwrap()[..12], b"S8A10001.114");
    assert_eq!(filename("0123456789ABCDEF").unwrap().len(), 16);
    assert!(filename("0123456789ABCDEFG").is_err());
    assert!(filename("café.bin").is_err());
}

#[test]
fn kernel_filename_follows_the_oem_scheme() {
    assert_eq!(
        kernel_filename("SAT 8A10", "GENERAL", "1.00"),
        "S8A10000.100"
    );
    assert_eq!(kernel_filename("SAT 8A10", "ID72", "1.14"), "S8A10720.114");
    // Tags with no destination mapping fall back to a generated label.
    assert_eq!(kernel_filename("SAT 8A10", "OTHER", "1.00"), "KERNEL.100");
}

// A high-word-length call site; `with_1a91` toggles the required marker.
fn high_word_site(k: &mut [u8], at: usize, with_1a91: bool, decoder: [u8; 4]) {
    k[at - 4..at].copy_from_slice(&[0x79, 9, 0, 1]);
    if with_1a91 {
        k[at - 40..at - 38].copy_from_slice(&[0x1a, 0x91]);
    }
    const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
    k[at..at + 12].copy_from_slice(&ARGS);
    k[at + 12..at + 16].copy_from_slice(&decoder);
}

// A cleared-length call site; the flags select which sub-field is correct.
fn cleared_site(k: &mut [u8], at: usize, p12: bool, p16: bool, p22: bool, decoder: [u8; 4]) {
    let base = at - 24;
    k[base..base + 10].copy_from_slice(&[0x7a, 1, 0, 1, 0x12, 0, 0x1f, 0x90, 0x58, 0x60]);
    k[base + 12..base + 16].copy_from_slice(if p12 {
        &[0x1a, 0xc4, 0x01, 0]
    } else {
        &[0, 0, 0, 0]
    });
    k[base + 16..base + 18].copy_from_slice(if p16 { &[0x6b, 0xa4] } else { &[0, 0] });
    k[base + 22..base + 24].copy_from_slice(if p22 { &[0x18, 0x11] } else { &[0, 0] });
    const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
    k[at..at + 12].copy_from_slice(&ARGS);
    k[at + 12..at + 16].copy_from_slice(&decoder);
}

#[test]
fn legacy_decoder_target_prelude_variants_and_bounds() {
    // A non-0x5e opcode with a long prelude must be rejected; `|| -> &&`
    // on the opcode check would accept it.
    let mut wrong_op = vec![0u8; 0x1000];
    wrong_op[0x300 - 6..0x300].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
    wrong_op[0x300..0x30c].copy_from_slice(&[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0]);
    wrong_op[0x30c..0x310].copy_from_slice(&[0x5f, 0x40, 0x01, 0x00]);
    assert!(legacy_decoder_target(&wrong_op).is_none());

    // Valid high-word call site is recognized (guards its `==` and the final
    // `high || cleared` combinator).
    let mut hw = vec![0u8; 0x1000];
    high_word_site(&mut hw, 0x300, true, DECODER);
    assert_eq!(legacy_decoder_target(&hw), Some(DECODER));
    // High-word prefix without the 0x1a91 marker is not a site; `&& -> ||`
    // or `== -> !=` in that clause would wrongly accept it.
    let mut hw_no = vec![0u8; 0x1000];
    high_word_site(&mut hw_no, 0x300, false, DECODER);
    assert!(legacy_decoder_target(&hw_no).is_none());

    // Valid cleared-length call site is recognized (guards its `==` chain).
    let mut cl = vec![0u8; 0x1000];
    cleared_site(&mut cl, 0x300, true, true, true, DECODER);
    assert_eq!(legacy_decoder_target(&cl), Some(DECODER));
    // Each cleared sub-field, wrong in isolation, must reject (guards the
    // `&&` chain and its `==` operators).
    for (p12, p16, p22) in [
        (false, true, true),
        (true, false, true),
        (true, true, false),
    ] {
        let mut c = vec![0u8; 0x1000];
        cleared_site(&mut c, 0x300, p12, p16, p22, DECODER);
        assert!(legacy_decoder_target(&c).is_none());
    }

    // Target valid for `+ 4` but out of range for `* 4`.
    let mut small = vec![0u8; 0x200];
    small[0x180 - 6..0x180].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
    small[0x180..0x18c].copy_from_slice(&[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0]);
    small[0x18c..0x190].copy_from_slice(&DECODER);
    assert_eq!(legacy_decoder_target(&small), Some(DECODER));
}

#[test]
fn scaled_geometry_window_field_isolation() {
    let mut base = vec![0u8; 0x2000];
    with_legacy_site(&mut base, 0x300, DECODER);
    scaled_window(&mut base, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
    assert!(scaled_normal_geometry_from_kernel(&base).is_some());
    // Corrupt each marker field (w[6..8], w[10..12], w[16..18], w[22..28]):
    // the window must stop matching, so a `|| -> &&` on the field chain
    // (which would accept the near-match) is caught.
    for off in [0x406usize, 0x40a, 0x410, 0x416] {
        let mut k = base.clone();
        k[off] ^= 0xff;
        assert!(scaled_normal_geometry_from_kernel(&k).is_none());
    }
}

fn front_kernel_field(mut mutate: impl FnMut(&mut Vec<u8>)) -> Vec<u8> {
    let mut k = front_kernel();
    mutate(&mut k);
    be32_fix(&mut k, 0xff00);
    k
}

#[test]
fn encode_kernel_second_guard_isolation() {
    let valid = front_kernel();
    let b = KernelBuild::from_seed(1);
    assert!(encode_kernel_envelope(&valid, "PIONEER BDR-TEST", &b).is_ok());
    // hardware length != 8 (still starts "SAT ") -> rejected.
    let hw7 = front_kernel_field(|k| k[0x1000..0x1008].copy_from_slice(b"SAT 8A1 "));
    assert!(encode_kernel_envelope(&hw7, "PIONEER BDR-TEST", &b).is_err());
    // empty kernel tag -> rejected.
    let tag0 = front_kernel_field(|k| k[0x1008..0x1010].copy_from_slice(b"        "));
    assert!(encode_kernel_envelope(&tag0, "PIONEER BDR-TEST", &b).is_err());
    // empty version2 -> rejected.
    let v20 = front_kernel_field(|k| k[0x1010..0x1014].copy_from_slice(b"    "));
    assert!(encode_kernel_envelope(&v20, "PIONEER BDR-TEST", &b).is_err());
    // A date of exactly 10 chars is valid (isolates `> 10` vs `== 10`/`>= 10`).
    assert!(encode_kernel_envelope(
        &valid,
        "PIONEER BDR-TEST",
        &KernelBuild {
            revision: "1.00",
            date: "0123456789",
            key: KernelKeySource::Seed(1),
        }
    )
    .is_ok());
}

#[test]
fn encode_pair_guard_isolation() {
    let kernel = front_kernel();
    let s = a_signer();
    let n = normal_image(0x2000);
    assert!(encode_encrypted_pair(&base_inputs(&kernel, &n), NormalSignature::Sign(&s)).is_ok());
    // A larger valid normal still works (isolates `< 0x2000` vs `> 0x2000`).
    let big = normal_image(0x4000);
    assert!(encode_encrypted_pair(&base_inputs(&kernel, &big), NormalSignature::Sign(&s)).is_ok());
    // normal below 0x2000 -> rejected.
    let small = normal_image(0x1000);
    assert!(
        encode_encrypted_pair(&base_inputs(&kernel, &small), NormalSignature::Sign(&s)).is_err()
    );
    // normal length not a multiple of 0x100 (be32 still zero) -> rejected.
    let misaligned = normal_image(0x2080);
    assert!(encode_encrypted_pair(
        &base_inputs(&kernel, &misaligned),
        NormalSignature::Sign(&s)
    )
    .is_err());
    // Empty normal_revision -> rejected (not re-checked by encode_kernel).
    let mut empty_rev = base_inputs(&kernel, &n);
    empty_rev.normal_revision = "";
    assert!(encode_encrypted_pair(&empty_rev, NormalSignature::Sign(&s)).is_err());
    // Empty normal_date -> rejected (an empty date is accepted by build_header,
    // so this isolates the `is_empty` branch of the date guard).
    let mut empty_date = base_inputs(&kernel, &n);
    empty_date.normal_date = "";
    assert!(encode_encrypted_pair(&empty_date, NormalSignature::Sign(&s)).is_err());
    // A 10-char date is valid (isolates `> 10` vs `== 10`/`>= 10`).
    let mut date10 = base_inputs(&kernel, &n);
    date10.normal_date = "0123456789";
    assert!(encode_encrypted_pair(&date10, NormalSignature::Sign(&s)).is_ok());
    // An id with more than two tokens is valid (isolates `< 2` vs `> 2`).
    let mut three = base_inputs(&kernel, &n);
    three.envelope_id = "PIONEER BD RW BDR-TEST";
    assert!(encode_encrypted_pair(&three, NormalSignature::Sign(&s)).is_ok());
}

#[test]
fn kernel_layout_requires_full_compare_pair() {
    // [reg,0xfe] without the matching [reg,0xf0] at +6 must not count as a
    // dispatcher compare pair; `&& -> ||` would count it.
    let mut k = vec![0u8; 0x2000];
    k[0x40] = 0xae;
    k[0x41] = 0xfe;
    assert!(kernel_layout_from_image(&k).is_none());
}

#[test]
fn normal_authentication_valid_scaled_requires_zero_checksum() {
    let mut kernel = vec![0u8; 0x2000];
    with_legacy_site(&mut kernel, 0x300, DECODER);
    scaled_window(&mut kernel, 0x400, 0x2400, 0x10600, 0x2000, DECODER);
    write_branch(&mut kernel, 0x600, [0x100, 0x200]);
    assert_eq!(
        normal_authentication_from_kernel(&kernel),
        Some(NormalAuthentication::ScaledChecksumOnly)
    );
    // A scaled normal whose decoded image starts PIONEER but is NOT
    // big-endian-sum-zero must be rejected; `&& -> ||` on the final check
    // would accept it on the PIONEER prefix alone.
    let mut image = vec![0u8; 0x2000];
    image[..8].copy_from_slice(b"PIONEER ");
    image[0x400] = 1; // non-zero checksum
    let key = make_key(0x47d001, 0x200);
    let mut normal = vec![0u8; 0x200]; // header region is irrelevant here
    normal.extend_from_slice(&key);
    normal.extend_from_slice(
        &transform_with_policy(&image, &key, true, false, &[0x100, 0x200]).unwrap(),
    );
    assert_eq!(normal.len(), 0x2400);
    assert!(!normal_authentication_valid(&normal, &kernel));
}

#[test]
fn validate_pair_inner_guard_isolation() {
    let kernel = front_kernel();
    let n = normal_image(0x2000);
    let s = a_signer();
    let pair = encode_encrypted_pair(&base_inputs(&kernel, &n), NormalSignature::Sign(&s)).unwrap();
    validate_encrypted_pair(&pair, &kernel, &n).unwrap();

    // Tamper the signature region only: structure and images stay valid, so
    // only the signature check fails. A `|| -> &&` would skip it and pass.
    let mut tampered = EncryptedPair {
        kernel: pair.kernel.clone(),
        normal: pair.normal.clone(),
    };
    tampered.normal[0x180] ^= 1;
    assert!(validate_encrypted_pair(&tampered, &kernel, &n).is_err());

    // A different (but same-shape) kernel image: only the kernel-image
    // comparison fails.
    let other_k = front_kernel_field(|k| k[0x6000] ^= 1);
    assert!(validate_encrypted_pair(&pair, &other_k, &n).is_err());

    // A different (same-length) normal image: only the normal-image
    // comparison fails.
    let mut other_n = n.clone();
    other_n[0x50] ^= 1;
    assert!(validate_encrypted_pair(&pair, &kernel, &other_n).is_err());
}

#[test]
fn encode_kernel_envelope_rejects_bad_identity_and_image() {
    let k = front_kernel();
    assert!(encode_kernel_envelope(&k, "PIONEER BDR-TEST", &KernelBuild::from_seed(1)).is_ok());
    // Wrong image length.
    assert!(
        encode_kernel_envelope(&k[..0xfffc], "PIONEER BDR-TEST", &KernelBuild::from_seed(1))
            .is_err()
    );
    // Broken big-endian checksum.
    let mut bad_sum = k.clone();
    bad_sum[0x3000] ^= 1;
    assert!(
        encode_kernel_envelope(&bad_sum, "PIONEER BDR-TEST", &KernelBuild::from_seed(1)).is_err()
    );
    // Missing SAT identity (checksum re-fixed so only SAT differs).
    let mut no_sat = k.clone();
    no_sat[0x1000] = b'X';
    be32_fix(&mut no_sat, 0xff00);
    assert!(
        encode_kernel_envelope(&no_sat, "PIONEER BDR-TEST", &KernelBuild::from_seed(1)).is_err()
    );
    // Envelope ID without a model token.
    assert!(encode_kernel_envelope(&k, "PIONEER", &KernelBuild::from_seed(1)).is_err());
    // Non-ASCII identity.
    assert!(encode_kernel_envelope(&k, "PIONEER BDR-É", &KernelBuild::from_seed(1)).is_err());
    // Empty revision and too-long date.
    assert!(encode_kernel_envelope(
        &k,
        "PIONEER BDR-TEST",
        &KernelBuild {
            revision: "",
            date: "00/00/00",
            key: KernelKeySource::Seed(1)
        }
    )
    .is_err());
    assert!(encode_kernel_envelope(
        &k,
        "PIONEER BDR-TEST",
        &KernelBuild {
            revision: "1.00",
            date: "0123456789A",
            key: KernelKeySource::Seed(1)
        }
    )
    .is_err());
}

#[test]
fn encode_encrypted_pair_rejects_malformed_normal_and_exceptions() {
    let kernel = front_kernel();
    let normal = normal_image(0x2000);
    let s = a_signer();
    assert!(
        encode_encrypted_pair(&base_inputs(&kernel, &normal), NormalSignature::Sign(&s)).is_ok()
    );

    // Normal not a multiple of 0x100.
    let mut odd = normal.clone();
    odd.extend_from_slice(&[0u8; 4]);
    assert!(encode_encrypted_pair(&base_inputs(&kernel, &odd), NormalSignature::Sign(&s)).is_err());

    // Normal missing the PIONEER prefix (checksum re-fixed).
    let mut no_pioneer = normal.clone();
    let fix_at = no_pioneer.len() - 0x100;
    no_pioneer[0] = b'X';
    be32_fix(&mut no_pioneer, fix_at);
    assert!(encode_encrypted_pair(
        &base_inputs(&kernel, &no_pioneer),
        NormalSignature::Sign(&s)
    )
    .is_err());

    // Declared size (bytes 20..24) disagreeing with the actual length.
    let mut wrong_declared = normal.clone();
    let fix_at = wrong_declared.len() - 0x100;
    wrong_declared[20..24].copy_from_slice(&0x3000u32.to_be_bytes());
    be32_fix(&mut wrong_declared, fix_at);
    assert!(encode_encrypted_pair(
        &base_inputs(&kernel, &wrong_declared),
        NormalSignature::Sign(&s)
    )
    .is_err());

    // Broken big-endian checksum on an otherwise valid Normal.
    let mut bad_sum = normal.clone();
    bad_sum[0x44] ^= 1;
    assert!(
        encode_encrypted_pair(&base_inputs(&kernel, &bad_sum), NormalSignature::Sign(&s)).is_err()
    );

    // A XOR exception offset outside the Normal image is rejected.
    let big_exc_kernel = front_kernel_with([0x100, 0x4000]);
    assert!(encode_encrypted_pair(
        &base_inputs(&big_exc_kernel, &normal),
        NormalSignature::Sign(&s)
    )
    .is_err());

    // A non-unique XOR branch policy is rejected.
    let mut two_branches = front_kernel();
    write_branch(&mut two_branches, 0x600, [0x100, 0x200]);
    be32_fix(&mut two_branches, 0xff00);
    assert!(encode_encrypted_pair(
        &base_inputs(&two_branches, &normal),
        NormalSignature::Sign(&s)
    )
    .is_err());
}

const ID: &str = "PIONEER BDR-TEST";

fn kernel_err(k: &[u8], id: &str, rev: &str, date: &str) -> Error {
    encode_kernel_envelope(
        k,
        id,
        &KernelBuild {
            revision: rev,
            date,
            key: KernelKeySource::Seed(1),
        },
    )
    .unwrap_err()
}

#[test]
fn encode_kernel_envelope_exact_errors_per_guard() {
    let k = front_kernel();
    let structure = Error::KernelStructure;
    let incomplete = Error::KernelIncomplete;
    // First guard: length, checksum, SAT identity.
    assert_eq!(kernel_err(&k[..0xfffc], ID, "1.00", "00/00/00"), structure);
    let mut bad_sum = k.clone();
    bad_sum[0x3000] ^= 1;
    assert_eq!(kernel_err(&bad_sum, ID, "1.00", "00/00/00"), structure);
    let no_sat = front_kernel_field(|k| k[0x1000] = b'X');
    assert_eq!(kernel_err(&no_sat, ID, "1.00", "00/00/00"), structure);
    // Second guard: each condition alone.
    let hw7 = front_kernel_field(|k| k[0x1000..0x1008].copy_from_slice(b"SAT 8A1 "));
    assert_eq!(kernel_err(&hw7, ID, "1.00", "00/00/00"), incomplete);
    let tag0 = front_kernel_field(|k| k[0x1008..0x1010].copy_from_slice(b"        "));
    assert_eq!(kernel_err(&tag0, ID, "1.00", "00/00/00"), incomplete);
    let v20 = front_kernel_field(|k| k[0x1010..0x1014].copy_from_slice(b"    "));
    assert_eq!(kernel_err(&v20, ID, "1.00", "00/00/00"), incomplete);
    assert_eq!(kernel_err(&k, "PIONEER", "1.00", "00/00/00"), incomplete);
    assert_eq!(
        kernel_err(&k, "PIONEER BDR-\u{c9}", "1.00", "00/00/00"),
        incomplete
    );
    assert_eq!(
        kernel_err(&k, "PIONEER BDR-\x01", "1.00", "00/00/00"),
        incomplete
    );
    assert_eq!(
        kernel_err(&k, "PIONEER BDR-\x7f", "1.00", "00/00/00"),
        incomplete
    );
    assert_eq!(kernel_err(&k, ID, "", "00/00/00"), incomplete);
    assert_eq!(kernel_err(&k, ID, "1.00", ""), incomplete);
    assert_eq!(kernel_err(&k, ID, "1.00", "0123456789A"), incomplete);
    assert_eq!(kernel_err(&k, ID, "1.00", "00/00/0\u{c9}"), incomplete);
}

fn pair_err(i: &BuildInputs<'_>) -> Error {
    encode_encrypted_pair(i, NormalSignature::Sign(&a_signer())).unwrap_err()
}

#[test]
fn encode_pair_exact_errors_per_guard() {
    let kernel = front_kernel();
    let n = normal_image(0x2000);
    let structure = Error::ImageStructure;
    let incomplete = Error::ImageIncomplete;
    // Structure guard, each condition alone.
    assert_eq!(pair_err(&base_inputs(&kernel[..0xfffc], &n)), structure);
    assert_eq!(
        pair_err(&base_inputs(&kernel, &normal_image(0x1f00))),
        structure
    );
    assert_eq!(
        pair_err(&base_inputs(&kernel, &normal_image(0x2080))),
        structure
    );
    let mut bad_k = kernel.clone();
    bad_k[0x3000] ^= 1;
    assert_eq!(pair_err(&base_inputs(&bad_k, &n)), structure);
    let mut bad_n = n.clone();
    bad_n[0x44] ^= 1;
    assert_eq!(pair_err(&base_inputs(&kernel, &bad_n)), structure);
    let no_sat = front_kernel_field(|k| k[0x1000] = b'X');
    assert_eq!(pair_err(&base_inputs(&no_sat, &n)), structure);
    let mut no_pioneer = n.clone();
    no_pioneer[0] = b'X';
    be32_fix(&mut no_pioneer, 0x1f00);
    assert_eq!(pair_err(&base_inputs(&kernel, &no_pioneer)), structure);
    let mut declared = n.clone();
    declared[20..24].copy_from_slice(&0x3000u32.to_be_bytes());
    be32_fix(&mut declared, 0x1f00);
    assert_eq!(pair_err(&base_inputs(&kernel, &declared)), structure);
    // Identity guard, each condition alone.
    let hw7 = front_kernel_field(|k| k[0x1000..0x1008].copy_from_slice(b"SAT 8A1 "));
    assert_eq!(pair_err(&base_inputs(&hw7, &n)), incomplete);
    let tag0 = front_kernel_field(|k| k[0x1008..0x1010].copy_from_slice(b"        "));
    assert_eq!(pair_err(&base_inputs(&tag0, &n)), incomplete);
    let v20 = front_kernel_field(|k| k[0x1010..0x1014].copy_from_slice(b"    "));
    assert_eq!(pair_err(&base_inputs(&v20, &n)), incomplete);
    for id in [
        "PIONEER",
        "PIONEER BDR-\u{c9}",
        "PIONEER BDR-\x01",
        "PIONEER BDR-\x7f",
    ] {
        let mut i = base_inputs(&kernel, &n);
        i.envelope_id = id;
        assert_eq!(pair_err(&i), incomplete, "{id:?}");
    }
    let mut i = base_inputs(&kernel, &n);
    i.normal_revision = "";
    assert_eq!(pair_err(&i), incomplete);
    // Date guard, each condition alone.
    for date in ["", "0123456789A", "00/00/0\u{c9}"] {
        let mut i = base_inputs(&kernel, &n);
        i.normal_date = date;
        assert_eq!(pair_err(&i), Error::InvalidDate, "{date:?}");
    }
    // Exception guard: out of range, and in range but misaligned.
    let far = front_kernel_with([0x100, 0x4000]);
    assert_eq!(
        pair_err(&base_inputs(&far, &n)),
        Error::XorExceptionOutOfRange
    );
    let odd = front_kernel_with([0x100, 0x202]);
    assert_eq!(
        pair_err(&base_inputs(&odd, &n)),
        Error::XorExceptionOutOfRange
    );
}

#[test]
fn abi_check_rejects_only_unsatisfied_requirements() {
    let kernel = front_kernel();
    let call = |target: u32| {
        let mut n = vec![0u8; 0x10100];
        n[..8].copy_from_slice(b"PIONEER ");
        let l = n.len() as u32;
        n[20..24].copy_from_slice(&l.to_be_bytes());
        let t = target.to_be_bytes();
        n[0x3000..0x3004].copy_from_slice(&[0x5E, t[1], t[2], t[3]]);
        let fix = n.len() - 0x100;
        be32_fix(&mut n, fix);
        n
    };
    // Satisfied: the Kernel start is always provided.
    let ok = call(0x40_0000);
    assert!(crate::image::required_abi(&ok).is_some());
    assert!(crate::image::provided_abi(&kernel).is_some());
    encode_encrypted_pair(
        &base_inputs(&kernel, &ok),
        NormalSignature::Sign(&a_signer()),
    )
    .unwrap();
    // Unsatisfied: 0x400102 is inside a 6-byte instruction.
    let bad = call(0x40_0102);
    assert_eq!(pair_err(&base_inputs(&kernel, &bad)), Error::AbiMismatch);
}

#[test]
fn validate_pair_inner_exact_errors() {
    let kernel = front_kernel();
    let n = normal_image(0x2000);
    let s = a_signer();
    let pair = encode_encrypted_pair(&base_inputs(&kernel, &n), NormalSignature::Sign(&s)).unwrap();
    let bad = Error::InvalidSignedEnvelope;
    let mut p = pair.clone();
    p.kernel.pop();
    assert_eq!(validate_encrypted_pair(&p, &kernel, &n), Err(bad));
    let mut p = pair.clone();
    p.normal.push(0);
    assert_eq!(validate_encrypted_pair(&p, &kernel, &n), Err(bad));
    let mut p = pair.clone();
    p.normal[0x180] ^= 1;
    assert_eq!(validate_encrypted_pair(&p, &kernel, &n), Err(bad));
    // A zeroed-signature pair passes the unchecked path but fails the
    // checked one with exactly the signature error.
    let z = encode_encrypted_pair(&base_inputs(&kernel, &n), NormalSignature::Zeroed).unwrap();
    assert_eq!(validate_encrypted_pair(&z, &kernel, &n), Err(bad));
    validate_pair_inner(&z, &kernel, &n, false).unwrap();
    // Image mismatches are reported as round-trip errors.
    let other_k = front_kernel_field(|k| k[0x6000] ^= 1);
    assert_eq!(
        validate_encrypted_pair(&pair, &other_k, &n),
        Err(Error::RoundTripMismatch)
    );
    let mut other_n = n.clone();
    other_n[0x50] ^= 1;
    assert_eq!(
        validate_encrypted_pair(&pair, &kernel, &other_n),
        Err(Error::RoundTripMismatch)
    );
}

#[test]
fn kernel_layout_mismatch_alone_is_a_round_trip_error() {
    let kernel = front_kernel();
    let n = normal_image(0x2000);
    let pair = encode_encrypted_pair(
        &base_inputs(&kernel, &n),
        NormalSignature::Sign(&a_signer()),
    )
    .unwrap();
    // Re-encode the same Kernel image as a derived-key envelope. Every
    // length and image comparison still holds; only the layout differs.
    let seed = 0x123456u32;
    let key = make_key(seed, 0x1000);
    let mut enc = pair.kernel[..0x200].to_vec();
    enc.extend_from_slice(&transform(&kernel, &key, true).unwrap());
    let steps = 0x11200 - 0x200 - 16 + 0x1000;
    let final_state = super::super::jump_seed(seed, steps, false);
    let trailer_start = super::super::jump_seed(final_state, 0xff0, true);
    enc.extend_from_slice(&make_key(trailer_start, 0x1000));
    let derived = decode_envelope(&enc).expect("derived Kernel decodes");
    assert_eq!(derived.info.layout, Layout::KernelDerived);
    assert_eq!(derived.image, kernel);
    let swapped = EncryptedPair {
        kernel: enc,
        normal: pair.normal.clone(),
    };
    assert_eq!(
        validate_encrypted_pair(&swapped, &kernel, &n),
        Err(Error::RoundTripMismatch)
    );
}
