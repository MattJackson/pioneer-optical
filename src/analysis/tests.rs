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
        },
        regions: vec![region.clone()],
        diagnostics: Vec::new(),
    };
    references::identify(&mut analysis);
    let reference = &analysis.regions[0].references[0];
    assert_eq!(reference.instruction, 260..264);
    assert_eq!(reference.operand, 261..264);
    assert_eq!(reference.target, 0x400180);
    region.bytes = Cow::Borrowed(&bytes[..8]);
    region.size = 8;
    region.stored = 0..8;
    analysis.regions = vec![region];
    references::identify(&mut analysis);
    assert!(analysis.regions[0].references.is_empty());
}
