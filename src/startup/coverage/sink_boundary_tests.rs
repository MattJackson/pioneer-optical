use super::*;

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let mut normal = alloc::vec![0xff; 0x1b0000];
    for (span, shape) in SPANS.iter().zip(SHAPES) {
        normal[span.clone()].copy_from_slice(shape);
    }
    (normal, alloc::vec![0xff; 0x10000])
}

#[test]
fn complete_native_ownership_excludes_only_the_supplied_cross_instruction_literal() {
    let (normal, kernel) = fixture();
    let certificate = bind(&normal, &kernel).unwrap();
    assert_eq!(certificate.protected(), SPANS);
    assert!(certificate.accepts_kernel(&kernel));
    assert!(certificate.is_cross_instruction_literal(0xdc430, 4));
    for (at, len) in [
        (0xdc42e, 4),
        (0xdc432, 4),
        (0xdc430, 2),
        (0xdc430, 6),
        (0x1000, 4),
    ] {
        assert!(!certificate.is_cross_instruction_literal(at, len));
    }
    assert_eq!(bind(&normal, &[]), Err(BoundaryFailure::MissingKernel));
    assert!(!certificate.accepts_kernel(&[]));
    assert_eq!(
        decode(&normal, BODY).unwrap().last(),
        Some(&(0xdc59c..0xdc59e))
    );
    assert_eq!(
        decode(&normal, SPANS[1].clone()).unwrap().last(),
        Some(&(0xdbb96..0xdbb98))
    );
}

#[test]
fn every_complete_span_and_fixed_operand_is_mandatory() {
    let (normal, kernel) = fixture();
    // Each entire copied span is protected, including table fields not used
    // directly by the reset body's two callers and the last callback RTS.
    for span in SPANS {
        for at in span {
            let mut changed = normal.clone();
            changed[at] ^= 1;
            assert_eq!(
                bind(&changed, &kernel),
                Err(BoundaryFailure::Shape),
                "{at:x}"
            );
        }
    }
}

#[test]
fn actual_normal_and_kernel_entries_into_operands_refuse_before_exclusion() {
    let (normal, kernel) = fixture();
    for opcode in [0, 0x5e, 0x5a] {
        let mut changed = normal.clone();
        changed[0x1800..0x1804].copy_from_slice(&[opcode, 0x4e, 0xc4, 0x30]);
        assert_eq!(
            bind(&changed, &kernel),
            Err(BoundaryFailure::InteriorEntry {
                kernel: false,
                at: 0x1800,
                target: 0x4ec430,
            })
        );
        let mut changed = kernel.clone();
        changed[0x8000..0x8004].copy_from_slice(&[opcode, 0x4e, 0xc4, 0x30]);
        assert_eq!(
            bind(&normal, &changed),
            Err(BoundaryFailure::InteriorEntry {
                kernel: true,
                at: 0x8000,
                target: 0x4ec430,
            })
        );
        assert!(!bind(&normal, &kernel).unwrap().accepts_kernel(&changed));
    }
    // Every even interior is inventoried, not only the collision's operand.
    let certificate = bind(&normal, &kernel).unwrap();
    for &target in &certificate.forbidden_instruction_entries {
        let mut changed = kernel.clone();
        let address = target.to_be_bytes();
        changed[0x8000..0x8004].copy_from_slice(&[0x5e, address[1], address[2], address[3]]);
        assert!(!certificate.accepts_kernel(&changed), "{target:x}");
    }
}

#[test]
fn raw_relative_reference_grammar_preserves_component_base_alignment_and_tail() {
    let target = 0x410020;
    for (bytes, base, offset) in [
        (alloc::vec![0x40, 0x1e], 0x410000, 0),
        (alloc::vec![0x55, 0x1e], 0x410000, 0),
        (alloc::vec![0x58, 0x60, 0, 0x1c], 0x410000, 0),
        (alloc::vec![0x5c, 0, 0, 0x1c], 0x410000, 0),
        (alloc::vec![0x55, 0xfe], 0x400000, 0x10020),
        (alloc::vec![0x5c, 0, 0xff, 0xfc], 0x400000, 0x10020),
        (alloc::vec![0xff, 0x55, 0x1c], 0x410000, 1),
    ] {
        assert_eq!(
            interior_entry(&bytes, offset, base, &[target]),
            Some((offset + (offset & 1), target))
        );
    }
    assert_eq!(interior_entry(&[0x55], 0, 0x410000, &[target]), None);
    assert_eq!(
        interior_entry(&[0xff, 0x55, 0x1d], 0, 0x410000, &[target]),
        None
    );
    // A complete MOV immediate remains raw address-taking, never excluded.
    assert_eq!(
        interior_entry(&[0x7a, 0, 0, 0x4e, 0xc4, 0x30], 0, 0x410000, &[0x4ec430]),
        Some((2, 0x4ec430))
    );
}

#[test]
fn duplicate_owner_and_stored_range_splits_refuse() {
    let (mut normal, kernel) = fixture();
    normal[0x10000..0x10000 + SHAPES[0].len()].copy_from_slice(SHAPES[0]);
    assert_eq!(bind(&normal, &kernel), Err(BoundaryFailure::AmbiguousOwner));
    let span = BODY;
    assert!(!contained(&[span.start..0xdc432, 0xdc432..span.end], &span));
    assert!(!contained(&[0..span.start, span.end..normal.len()], &span));
    assert!(contained(core::slice::from_ref(&span), &span));
    let (mut normal, kernel) = fixture();
    // Malformed compression never falls back to treating its payload as code.
    normal[0x1000..0x1004].copy_from_slice(b"COMP");
    assert_eq!(bind(&normal, &kernel), Err(BoundaryFailure::StoredRegions));
    let (mut normal, kernel) = fixture();
    let compressed = miniz_oxide::deflate::compress_to_vec_zlib(&[0x5e; 32], 6);
    let start = 0xdc420;
    normal[start..start + 4].copy_from_slice(&32u32.to_be_bytes());
    normal[start + 4..start + 4 + compressed.len()].copy_from_slice(&compressed);
    normal[0x1000..0x1004].copy_from_slice(b"COMP");
    normal[0x1004..0x1008].copy_from_slice(&(NORMAL_BASE + start as u32).to_be_bytes());
    normal[0x1008..0x100c]
        .copy_from_slice(&(NORMAL_BASE + start as u32 + compressed.len() as u32).to_be_bytes());
    normal[0x100c..0x1010].fill(0xff);
    assert!(
        crate::image::regions(&normal).is_some(),
        "valid COMP decoding"
    );
    assert_eq!(bind(&normal, &kernel), Err(BoundaryFailure::StoredRegions));
}

#[cfg(feature = "envelope")]
#[test]
#[ignore = "requires exact paired authenticated envelopes in PIONEER_CORPUS"]
fn authenticated_bdr211m_boundary_positive_mutations_and_phase_preservation() {
    use crate::{envelope::Update, filters::phase::native};
    use sha2::{Digest, Sha256};
    let root = std::path::PathBuf::from(std::env::var("PIONEER_CORPUS").unwrap());
    let load = |hash: &str| {
        let bytes = std::fs::read(root.join(alloc::format!("{hash}.enc"))).unwrap();
        assert_eq!(alloc::format!("{:x}", Sha256::digest(&bytes)), hash);
        bytes
    };
    let update = Update::load(
        &load("437f8a0fa28f326f1432b5c127951faed207dfdb9646462bc59bd9008f0296cf"),
        &load("12183b7e321946cab7911cf5573d0198d928b4b4d5982721c15e6bb238086ee6"),
    )
    .unwrap();
    let installed = Update::load(
        &load("34086ec0b5fbaf14802ffd307c1a74b519dcc21dc5bf8f89bfb93c9966ca3662"),
        &load("0a486f059bcaf5f9e0b5ad21ca94b5a3da6f1b583cd24f09cdf653ec235321aa"),
    )
    .unwrap();
    assert!(super::super::sinks::discover(&installed.normal().image)
        .unwrap()
        .accepts_kernel(&installed.kernel().image));
    assert!(bind(&installed.normal().image, &installed.kernel().image).is_err());
    let normal = &update.normal().image;
    let kernel = &update.kernel().image;
    let certificate = bind(normal, kernel).unwrap();
    assert_eq!(certificate.protected(), SPANS);
    assert!(
        super::super::sinks::discover(normal).is_none(),
        "old Normal-only discovery remains conservative"
    );
    for (at, replacement) in [
        (0x1000, &[0x5e, 0x4e, 0xc4, 0x30][..]),
        (0x1a6683, &[0x44]),
        (0xdc4a9, &[0xde]),
        (0xdaedd, &[0x06]),
        (0xdc59c, &[0, 0]),
        (0xdbb96, &[0, 0]),
    ] {
        let mut changed = normal.clone();
        changed[at..at + replacement.len()].copy_from_slice(replacement);
        assert!(bind(&changed, kernel).is_err(), "{at:x}");
    }
    let mut changed_kernel = kernel.clone();
    changed_kernel[0x8000..0x8004].copy_from_slice(&[0x5e, 0x4e, 0xc4, 0x30]);
    assert!(!certificate.accepts_kernel(&changed_kernel));
    assert!(bind(normal, &changed_kernel).is_err());
    let mut unowned = normal.clone();
    unowned[0x1800..0x1804].copy_from_slice(&[0, 0x45, 0x6e, 0xb8]);
    assert!(!bind(&unowned, kernel)
        .unwrap()
        .is_cross_instruction_literal(0x1800, 4));
    let crate::image::layout::Observation::Known(phase) = native::discover_pair(normal) else {
        panic!("native phase")
    };
    let assignment = match phase.assignment {
        native::Assignment::Direct => native::Assignment::Swapped,
        native::Assignment::Swapped => native::Assignment::Direct,
    };
    let corrected = native::correct_pair(normal, assignment).unwrap();
    assert_ne!(&corrected, normal);
    for span in certificate.protected() {
        assert_eq!(normal[span.clone()], corrected[span]);
    }
    assert_eq!(bind(&corrected, kernel).unwrap(), certificate);
}
