use super::*;
use std::io::Write;

#[test]
fn table_records_preserve_source_order_and_bytes() {
    let bytes = b"SONY__NS1\0TDKBLDRBA\0VERBATIMa\0MEI___T01\0\xff\x12";
    let tables = tables::inspect(bytes);
    assert_eq!(tables.len(), 1);
    assert_eq!(tables[0].record_width, 10);
    assert_eq!(tables[0].records[2].value, "VERBATIMa");
    assert_eq!(tables[0].range, 0..40);
    assert!(tables::inspect(b"one isolated string\0").is_empty());
}
fn comp_image() -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&[0x5a; 512]).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut image = vec![0xff; 0x4000];
    let base = 0x410000u32;
    let start = base + 0x2000;
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
    image[0x1008..0x100c].copy_from_slice(&(start + compressed.len() as u32).to_be_bytes());
    image[0x2000..0x2004].copy_from_slice(&512u32.to_be_bytes());
    image[0x2004..0x2004 + compressed.len()].copy_from_slice(&compressed);
    image
}
#[test]
fn shared_comp_decoder_enforces_limits_before_expansion() {
    let image = comp_image();
    assert_eq!(
        envelope::inspect_streams(&image, 511, &mut || true).unwrap_err(),
        envelope::StreamError::Limit
    );
    let (_, streams) = envelope::inspect_streams(&image, 512, &mut || true)
        .unwrap()
        .unwrap();
    assert_eq!(streams[0].expanded, [0x5a; 512]);
    assert_eq!(
        envelope::inspect_streams(&image, 512, &mut || false).unwrap_err(),
        envelope::StreamError::Cancelled
    );
    assert!(envelope::inspect_streams(b"no streams", 512, &mut || true)
        .unwrap()
        .is_none());
    let mut bad = image;
    bad[0x1008..0x100c].copy_from_slice(&0u32.to_be_bytes());
    assert!(envelope::inspect_streams(&bad, 512, &mut || true).is_err());
}

#[test]
fn direct_reference_facts_are_extracted_from_one_image() {
    let mut bytes = [0x0c, 0x88].repeat(256);
    bytes[260..264].copy_from_slice(&[0x5e, 0x40, 0x01, 0x80]);
    let mut region = Region {
        id: 0,
        name: "Code".into(),
        stored: 0..bytes.len(),
        address: Some(0x400000),
        address_source: None,
        metadata: Vec::new(),
        stream: None,
        sha256: hash(&bytes),
        size: bytes.len(),
        tables: Vec::new(),
        references: Vec::new(),
        bytes: Cow::Borrowed(&bytes),
    };
    // Framing/target interpretation is image-local, independent of any comparison.
    let mut analysis = FirmwareAnalysis {
        startup_requirement: None,
        identity: Identity {
            family: None,
            family_scheme: "test",
            model: String::new(),
            component: "Kernel".into(),
            revision: String::new(),
            hardware: String::new(),
            codec: String::new(),
            sha256: hash(&bytes),
            size: bytes.len(),
            uhd: None,
            encoding_seed: None,
            filters: Vec::new(),
        },
        regions: vec![region.clone()],
        diagnostics: Vec::new(),
    };
    references::identify(&mut analysis, Options::default().expanded_bytes).unwrap();
    let reference = &analysis.regions[0].references[0];
    assert_eq!(reference.instruction, 260..264);
    assert_eq!(reference.operand, 261..264);
    assert_eq!(reference.target, 0x400180);
    region.bytes = Cow::Borrowed(&bytes[..262]);
    region.size = 262;
    region.stored = 0..262;
    analysis.regions = vec![region];
    references::identify(&mut analysis, Options::default().expanded_bytes).unwrap();
    assert!(analysis.regions[0].references.is_empty());
}

#[test]
fn derived_reference_memory_is_bounded_by_the_analysis_limit() {
    // One reference per two input bytes: 0x8000 references (~1.25 MiB on 64-bit).
    let bytes = [0x40, 0x02].repeat(0x8000);
    let region = Region {
        id: 0,
        name: "Code".into(),
        stored: 0..bytes.len(),
        address: Some(0x400000),
        address_source: None,
        metadata: Vec::new(),
        stream: None,
        sha256: hash(&bytes),
        size: bytes.len(),
        tables: Vec::new(),
        references: Vec::new(),
        bytes: Cow::Borrowed(&bytes),
    };
    let mut analysis = FirmwareAnalysis {
        startup_requirement: None,
        identity: Identity {
            family: None,
            family_scheme: "test",
            model: String::new(),
            component: "Kernel".into(),
            revision: String::new(),
            hardware: String::new(),
            codec: String::new(),
            sha256: hash(&bytes),
            size: bytes.len(),
            uhd: None,
            encoding_seed: None,
            filters: Vec::new(),
        },
        regions: vec![region],
        diagnostics: Vec::new(),
    };
    assert_eq!(
        references::identify(&mut analysis, 0x10000),
        Err(Error::ResourceLimit)
    );
    references::identify(&mut analysis, Options::default().expanded_bytes).unwrap();
    assert_eq!(analysis.regions[0].references.len(), 0x8000);
}

/// Keyed SAT 8A10 Normal whose body holds a synchronized H8 run with one JSR
/// to the COMP base, followed by `comp_image`'s stream. It carries no native
/// contracts, so its matrix identity is unresolved.
fn h8_comp_normal() -> Envelope {
    use crate::envelope::{builder::*, signature::SigningKey, synthetic_roundtrip_tests};
    let mut normal = comp_image();
    normal[..8].copy_from_slice(b"PIONEER ");
    normal[8..24].fill(0);
    let len = normal.len() as u32;
    normal[20..24].copy_from_slice(&len.to_be_bytes());
    normal[0x1100..0x1e00].copy_from_slice(&[0x0c, 0x88].repeat(0x680));
    normal[0x1200..0x1204].copy_from_slice(&[0x5e, 0x41, 0x00, 0x00]);
    let sum = normal.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    let fix = u32::from_be_bytes(normal[0x3f00..0x3f04].try_into().unwrap()).wrapping_sub(sum);
    normal[0x3f00..0x3f04].copy_from_slice(&fix.to_be_bytes());
    let kernel = synthetic_roundtrip_tests::front_kernel();
    let mut key = [0; 20];
    key[19] = 5;
    let encoded = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        },
        NormalSignature::Sign(&SigningKey::from_bytes(key).unwrap()),
    )
    .unwrap();
    let kernel = Envelope::load(&encoded.kernel).unwrap();
    let envelope = Envelope::load_with_kernel(&encoded.normal, &kernel).unwrap();
    assert_eq!(envelope.image, normal);
    assert_eq!(envelope.info().layout, envelope::Layout::Normal);
    envelope
}

fn reads(f: impl FnOnce()) -> usize {
    crate::comp_streams::READS.with(|reads| reads.set(0));
    f();
    crate::comp_streams::READS.with(|reads| reads.get())
}

#[test]
fn h8_references_do_not_depend_on_a_resolved_matrix_identity() {
    let envelope = h8_comp_normal();
    let analysis = envelope.analyze(Options::default(), &mut ()).unwrap();
    assert_eq!(analysis.identity.family, None);
    let targets: Vec<u32> = analysis
        .regions
        .iter()
        .flat_map(|r| &r.references)
        .map(|r| r.target)
        .collect();
    assert_eq!(targets, [0x410000]);
}

#[test]
fn over_limit_streams_refuse_before_any_unbounded_native_discovery() {
    let envelope = h8_comp_normal();
    let mut result = None;
    let count = reads(|| {
        result = Some(
            envelope
                .analyze(
                    Options {
                        expanded_bytes: 511,
                    },
                    &mut (),
                )
                .map(|_| ()),
        );
    });
    assert_eq!(result, Some(Err(Error::ResourceLimit)));
    assert_eq!(count, 1, "only the caller-bounded stream read may run");
}

#[test]
fn filters_and_family_share_one_native_inspection() {
    let envelope = h8_comp_normal();
    let firmware = crate::compatibility::Firmware {
        hardware: &envelope.info().hardware_version,
        normal: &envelope.image,
        kernel: None,
    };
    let once = reads(|| {
        let context = crate::filters::Context::new(firmware);
        let _ = context.filters();
        let _ = crate::filters::identity::discover(&context);
    }) + reads(|| {
        let _ = crate::startup::discover(&envelope.image);
    });
    let analysis = reads(|| {
        envelope.analyze(Options::default(), &mut ()).unwrap();
    });
    assert_eq!(analysis, 1 + once);
}
