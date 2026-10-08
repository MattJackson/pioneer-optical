use super::*;
use crate::CodedError;

fn bytes(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect()
}
fn put(b: &mut [u8], at: usize, hex: &str) {
    let data = bytes(hex);
    b[at..at + data.len()].copy_from_slice(&data);
}
fn fix(b: &mut [u8]) {
    let end = b.len() - 4;
    b[end..].fill(0);
    let sum = b.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    b[end..].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
}

fn kernel(form: usize, fixed: bool) -> Vec<u8> {
    let mut k = vec![0; 0x10000];
    k[0x1000..0x1008].copy_from_slice(b"SAT TEST");
    k[0x2000..0x2010].copy_from_slice(b"PIONEER BD-RW   ");
    // Independent H8 instruction fixtures, with relocated code and descriptor.
    let descriptor = match form {
        0 => "18 bb 1a 91 0c b9 78 10 6a 2a 00 41 00 00 78 10 6a 28 00 40 20 00 1c 8a 47 04 5e 40 10 20 0a 0b ab 10 45 de",
        1 => "18 bb 1a a2 0c ba 78 20 6a 29 00 41 00 00 17 d1 78 20 6a 28 00 40 20 00 17 50 1d 01 47 04 5e 40 10 20 0a 0b ab 10 45 da",
        2 => "fc 10 1a b3 78 30 6a 21 00 41 00 00 78 30 6a 29 00 40 20 00 1c 91 47 04 5e 40 10 20 0b 73 1a 0c 46 e2",
        3 => "fb 10 1a a2 78 20 6a 21 00 41 00 00 78 20 6a 29 00 40 20 00 1c 91 46 0c 0b 72 1a 0b 46 e6 5e 41 00 14",
        _ => unreachable!(),
    };
    put(&mut k, 0x200, descriptor);
    if fixed {
        put(
            &mut k,
            0x400,
            "1a a2 7a 01 00 40 00 00 01 00 6d 10 0a 82 7a 21 00 41 20 00 46 f2 0f a2 47 02",
        );
        put(
            &mut k,
            0x600,
            "7a 01 00 01 00 00 7a 02 00 01 04 00 7a 00 00 01 14 00 5e 40 10 20",
        );
        put(&mut k, 0x700, "7a 21 00 00 24 00 58 60 00 20 7a 00 00 01 06 00 7a 01 00 00 20 00 7a 02 00 01 04 00 5e 40 10 20");
    } else {
        put(&mut k, 0x400, "1a a2 7a 01 00 40 00 00 01 00 6b 23 00 41 00 14 7a 13 00 41 00 00 40 06 01 00 6d 10 0a 82 1f b1 46 f6");
    }
    fix(&mut k);
    k
}
fn normal(fixed: bool) -> Vec<u8> {
    let mut n = vec![0; 0x2000];
    n[..16].copy_from_slice(b"PIONEER BD-RW   ");
    n[20..24].copy_from_slice(&(if fixed { 0x5e410100u32 } else { 0x2000 }).to_be_bytes());
    fix(&mut n);
    n
}

#[test]
fn all_descriptor_forms_resolve_both_length_rules() {
    for form in 0..4 {
        for fixed in [false, true] {
            let l = NormalLayout::from_kernel(&kernel(form, fixed), KERNEL_BASE).unwrap();
            let h = l.header_region();
            assert_eq!(h.address(), 0x410000);
            assert_eq!(h.length(), if fixed { 16 } else { 24 });
            let n = normal(fixed);
            assert_eq!(l.resolve(&n[..h.length()]).unwrap().length(), n.len());
            l.validate(&n).unwrap();
        }
    }
}

#[test]
fn malformed_instruction_evidence_is_not_a_match() {
    let original = kernel(0, false);
    for offset in [
        0x200, 0x202, 0x204, 0x206, 0x20e, 0x216, 0x218, 0x21a, 0x21e, 0x222, 0x400, 0x402, 0x408,
        0x410, 0x416, 0x417, 0x41a, 0x41c, 0x41e, 0x420, 0x421,
    ] {
        let mut k = original.clone();
        k[offset] ^= 1;
        fix(&mut k);
        assert!(
            NormalLayout::from_kernel(&k, KERNEL_BASE).is_err(),
            "mutation at {offset:x}"
        );
    }
}

#[test]
fn checksum_and_capture_address_are_required() {
    let k = kernel(0, false);
    for len in [0, 4, 0x1000, 0xffff] {
        assert_eq!(
            NormalLayout::from_kernel(&k[..len], KERNEL_BASE),
            Err(NormalLayoutError::InvalidKernel)
        );
    }
    let mut bad = k.clone();
    bad[0] ^= 1;
    assert_eq!(
        NormalLayout::from_kernel(&bad, KERNEL_BASE),
        Err(NormalLayoutError::InvalidKernel)
    );
    assert_eq!(
        NormalLayout::from_kernel(&k, 0),
        Err(NormalLayoutError::ConflictingGeometry)
    );
}

#[test]
fn contradictory_addresses_and_unbounded_references_are_rejected() {
    for (at, value) in [
        (0x40c, 0x410018),
        (0x412, 0x420000),
        (0x404, 0x3f0000),
        (0x20a, 0x420000),
        (0x212, 0x40fff8),
        (0x212, 0xffffffff),
        (0x21a, 0x5e500000),
        (0x21a, 0x5e401021),
    ] {
        let mut k = kernel(0, false);
        k[at..at + 4].copy_from_slice(&u32::to_be_bytes(value));
        fix(&mut k);
        assert!(
            NormalLayout::from_kernel(&k, KERNEL_BASE).is_err(),
            "field {at:x}"
        );
    }
}

#[test]
fn duplicate_or_competing_rules_are_ambiguous() {
    let mut k = kernel(0, false);
    k.copy_within(0x400..0x422, 0x800);
    fix(&mut k);
    assert_eq!(
        NormalLayout::from_kernel(&k, KERNEL_BASE),
        Err(NormalLayoutError::Ambiguous)
    );
    let mut k = kernel(0, false);
    k.copy_within(0x200..0x224, 0x800);
    fix(&mut k);
    assert_eq!(
        NormalLayout::from_kernel(&k, KERNEL_BASE),
        Err(NormalLayoutError::Ambiguous)
    );
    let mut k = kernel(0, false);
    let fixed = kernel(3, true);
    k[0x800..0x81a].copy_from_slice(&fixed[0x400..0x41a]);
    fix(&mut k);
    assert_eq!(
        NormalLayout::from_kernel(&k, KERNEL_BASE),
        Err(NormalLayoutError::Ambiguous)
    );
}

#[test]
fn fixed_extent_requires_independent_decoder_agreement() {
    for offset in [0x412, 0x712, 0x71c] {
        let mut k = kernel(3, true);
        k[offset] ^= 1;
        fix(&mut k);
        assert!(NormalLayout::from_kernel(&k, KERNEL_BASE).is_err());
    }
}

#[test]
fn code_can_move_but_must_remain_instruction_aligned() {
    let mut k = kernel(0, false);
    k.copy_within(0x200..0x224, 0x800);
    k[0x200..0x224].fill(0);
    k.copy_within(0x400..0x422, 0x900);
    k[0x400..0x422].fill(0);
    fix(&mut k);
    NormalLayout::from_kernel(&k, KERNEL_BASE).unwrap();
    k.copy_within(0x900..0x922, 0xa01);
    k[0x900..0x922].fill(0);
    fix(&mut k);
    assert_eq!(
        NormalLayout::from_kernel(&k, KERNEL_BASE),
        Err(NormalLayoutError::Unsupported)
    );
}

#[test]
fn normal_prefix_and_extent_are_checked_before_capture() {
    let l = NormalLayout::from_kernel(&kernel(0, false), KERNEL_BASE).unwrap();
    let n = normal(false);
    for size in [0, 15, 20, 23] {
        assert!(matches!(
            l.resolve(&n[..size]),
            Err(NormalLayoutError::ShortHeader { .. })
        ));
    }
    let mut n = n;
    for length in [0, 0x1f00, 0x2001, 0x800100, u32::MAX] {
        n[20..24].copy_from_slice(&length.to_be_bytes());
        assert_eq!(
            l.resolve(&n),
            Err(NormalLayoutError::InvalidLength { length })
        );
    }
    n[0] ^= 1;
    assert_eq!(l.resolve(&n), Err(NormalLayoutError::DescriptorMismatch));
}

#[test]
fn full_normal_must_have_exact_length_and_checksum() {
    let l = NormalLayout::from_kernel(&kernel(0, false), KERNEL_BASE).unwrap();
    let mut n = normal(false);
    assert!(matches!(
        l.validate(&n[..n.len() - 1]),
        Err(NormalLayoutError::ImageLength { .. })
    ));
    n[0x100] ^= 1;
    assert_eq!(l.validate(&n), Err(NormalLayoutError::ImageChecksum));
    n.push(0);
    assert!(matches!(
        l.validate(&n),
        Err(NormalLayoutError::ImageLength { .. })
    ));
}

#[test]
fn errors_have_distinct_stable_codes() {
    let errors = [
        NormalLayoutError::NotKernel,
        NormalLayoutError::InvalidKernel,
        NormalLayoutError::Unsupported,
        NormalLayoutError::Ambiguous,
        NormalLayoutError::ConflictingGeometry,
        NormalLayoutError::ShortHeader {
            expected: 24,
            actual: 1,
        },
        NormalLayoutError::DescriptorMismatch,
        NormalLayoutError::InvalidLength { length: 1 },
        NormalLayoutError::ImageLength {
            expected: 8192,
            actual: 1,
        },
        NormalLayoutError::ImageChecksum,
    ];
    let codes: std::collections::BTreeSet<_> = errors.iter().map(CodedError::code).collect();
    assert_eq!(codes.len(), errors.len());
    assert!(codes
        .iter()
        .all(|c| c.starts_with("pioneer.normal_layout.")));
}

#[test]
fn configured_corpus_layouts_and_complete_pairs() {
    // Private corpus stays outside the crate. TSV: expected(ok/unsupported),
    // decoded Kernel path, optional decoded Normal path. No model lookup.
    let Ok(path) = std::env::var("PIONEER_NORMAL_LAYOUT_CORPUS") else {
        return;
    };
    let manifest = std::fs::read_to_string(path).unwrap();
    let mut count = 0;
    for line in manifest.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        let k = std::fs::read(fields[1]).unwrap();
        let layout = NormalLayout::from_kernel(&k, KERNEL_BASE);
        if fields[0] == "unsupported" {
            assert!(layout.is_err(), "{}", fields[1]);
        } else {
            let layout = layout.unwrap_or_else(|e| panic!("{}: {e}", fields[1]));
            if let Some(path) = fields.get(2) {
                layout
                    .validate(&std::fs::read(path).unwrap())
                    .unwrap_or_else(|e| panic!("{path}: {e}"));
            }
        }
        count += 1;
    }
    assert!(count > 0);
    eprintln!("validated {count} configured Kernel/Normal layout cases");
}

#[test]
fn envelope_api_uses_decoded_kernel_and_rejects_other_components() {
    let mut image = super::super::synthetic_roundtrip_tests::front_kernel();
    let geometry = kernel(0, false);
    image[0x200..0x224].copy_from_slice(&geometry[0x200..0x224]);
    image[0x400..0x422].copy_from_slice(&geometry[0x400..0x422]);
    image[0x2000..0x2010].copy_from_slice(&geometry[0x2000..0x2010]);
    fix(&mut image);
    let encoded = builder::encode_kernel_envelope(
        &image,
        "PIONEER BDR-TEST",
        &builder::KernelBuild::from_seed(17),
    )
    .unwrap();
    let mut envelope = crate::envelope::Envelope::load(&encoded).unwrap();
    assert_eq!(
        envelope.normal_layout().unwrap(),
        NormalLayout::from_kernel(&image, KERNEL_BASE).unwrap()
    );
    envelope.info.kind = crate::ComponentKind::Normal;
    assert_eq!(envelope.normal_layout(), Err(NormalLayoutError::NotKernel));
}
