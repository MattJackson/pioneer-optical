use super::*;

#[test]
fn lcg_seed_and_transform_roundtrip() {
    let seed = 0x4a6d5e;
    let key = make_key(seed, 0x1000);
    assert_eq!(recover_seed(&key[..16]), Some(seed));
    let tail = make_key(jump_seed(seed, 0x11000, false), 16);
    let recovered = recover_seed(&tail).unwrap();
    assert_eq!(jump_seed(recovered, 0x11000, true), seed);
    let plain = b"PIONEER BDR-US04";
    let cipher = transform(plain, &key, true).unwrap();
    assert_eq!(transform(&cipher, &key, false).unwrap(), plain);
    let reverse_cipher = transform_with_rotation(plain, &key, true, true).unwrap();
    assert_eq!(
        transform_with_rotation(&reverse_cipher, &key, false, true).unwrap(),
        plain
    );
    assert_ne!(cipher, reverse_cipher);
}

#[test]
fn incomplete_normal_reports_declared_length_without_decoding_as_complete() {
    let mut envelope = include_bytes!("../../tests/fixtures/id43.header").to_vec();
    envelope.resize(0x200, 0);
    let key = make_key(0x47d001, 0x10000);
    envelope.extend_from_slice(&key);
    let mut image = vec![0u8; 64];
    image[..16].copy_from_slice(b"PIONEER BDR-US04");
    image[20..24].copy_from_slice(&128u32.to_be_bytes());
    envelope.extend_from_slice(&transform(&image, &key, true).unwrap());
    assert_eq!(normal_length_mismatch(&envelope), Some((128, 64)));
    assert!(decode_envelope(&envelope).is_none());
    image[20..24].copy_from_slice(&64u32.to_be_bytes());
    envelope.truncate(0x10200);
    envelope.extend_from_slice(&transform(&image, &key, true).unwrap());
    assert_eq!(normal_length_mismatch(&envelope), None);
    assert!(decode_envelope(&envelope).is_some());
}

#[test]
fn uniform_ranges_only_report_long_zero_or_ff_runs() {
    let mut image = vec![0xaa; 16];
    image.extend([0xff; 257]);
    image.extend([0x00; 256]);
    image.extend([0x7f; 300]);
    assert_eq!(
        uniform_ranges(&image, 256)
            .iter()
            .map(|r| (r.offset, r.length, r.byte))
            .collect::<Vec<_>>(),
        [(16, 257, 0xff), (273, 256, 0x00)]
    );
}

#[test]
fn comp_directory_requires_complete_stream_and_unique_base() {
    let expanded = vec![0x5a; 512];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder.write_all(&expanded).unwrap();
    let compressed = encoder.finish().unwrap();
    let mut image = vec![0xff; 0x4000];
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    let base = 0x410000u32;
    let start = base + 0x2000;
    let end = start + compressed.len() as u32;
    image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
    image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
    image[0x2000..0x2004].copy_from_slice(&(expanded.len() as u32).to_be_bytes());
    image[0x2004..0x2004 + compressed.len()].copy_from_slice(&compressed);
    let (found_base, streams) = comp_streams(&image).unwrap();
    assert_eq!(found_base, base);
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].expanded, expanded);
    assert!(streams[0].info.recompresses_exactly);
    image[0x2004 + compressed.len() - 1] ^= 1;
    assert!(comp_streams(&image).is_none());
}

#[test]
fn rebuild_last_comp_preserves_earlier_bytes_and_reparses() {
    let old_expanded = vec![0x5a; 512];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder.write_all(&old_expanded).unwrap();
    let old_compressed = encoder.finish().unwrap();
    let mut image = vec![0xff; 0x2100];
    image[..8].copy_from_slice(b"PIONEER ");
    image[20..24].copy_from_slice(&0x2100u32.to_be_bytes());
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    let base = 0x410000u32;
    let start = base + 0x2000;
    let end = start + old_compressed.len() as u32;
    image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
    image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
    image[0x2000..0x2004].copy_from_slice(&(old_expanded.len() as u32).to_be_bytes());
    image[0x2004..0x2004 + old_compressed.len()].copy_from_slice(&old_compressed);
    assert_eq!(rebuild_last_comp(&image, &old_expanded).unwrap(), image);
    let new_expanded = vec![0xa5; 4096];
    let rebuilt = rebuild_last_comp(&image, &new_expanded).unwrap();
    assert_eq!(&rebuilt[..20], &image[..20]);
    assert_eq!(rebuilt[0x1004..0x1008], image[0x1004..0x1008]);
    assert_eq!(
        u32::from_be_bytes(rebuilt[20..24].try_into().unwrap()) as usize,
        rebuilt.len()
    );
    assert_eq!(comp_streams(&rebuilt).unwrap().1[0].expanded, new_expanded);
    image[0x100c..0x1010].copy_from_slice(&end.to_be_bytes());
    assert!(rebuild_last_comp(&image, &new_expanded).is_none());
}

#[test]
fn rebuild_last_comp_on_local_ud04_corpus_if_present() {
    let path =
        std::path::Path::new("hoard/models/BDR-UD04/firmware/1.11EU/BDR-UD04_FW111EU.fw.bin");
    let Ok(envelope) = std::fs::read(path) else {
        return;
    };
    let decoded = decode_envelope(&envelope).unwrap();
    let (_, streams) = comp_streams(&decoded.image).unwrap();
    let original_last = &streams.last().unwrap().expanded;
    assert_eq!(
        rebuild_last_comp(&decoded.image, original_last).unwrap(),
        decoded.image
    );
    let mut modified = original_last.clone();
    modified[0] ^= 1;
    let mut state = 0x1234_5678u32;
    for _ in 0..4096 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        modified.push(state as u8);
    }
    let rebuilt = rebuild_last_comp(&decoded.image, &modified).unwrap();
    assert!(rebuilt.len() > decoded.image.len());
    let (_, rebuilt_streams) = comp_streams(&rebuilt).unwrap();
    assert_eq!(rebuilt_streams.last().unwrap().expanded, modified);
    let encoded = decoded.repack_resized_normal(&rebuilt).unwrap();
    assert_eq!(decode_envelope(&encoded).unwrap().image, rebuilt);
}

#[test]
fn live_main_carve_requires_mapped_complete_comp_image() {
    let expanded = vec![0x42; 512];
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder.write_all(&expanded).unwrap();
    let compressed = encoder.finish().unwrap();
    let base = 0x10000u32;
    let mut dump = vec![0xff; 0x15000];
    let image = &mut dump[base as usize..base as usize + 0x4000];
    image[..8].copy_from_slice(b"PIONEER ");
    image[20..24].copy_from_slice(&0x4000u32.to_be_bytes());
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    let start = base + 0x2000;
    let end = start + compressed.len() as u32;
    image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
    image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
    image[0x2000..0x2004].copy_from_slice(&(expanded.len() as u32).to_be_bytes());
    image[0x2004..0x2004 + compressed.len()].copy_from_slice(&compressed);
    let carved = carve_live_main(&dump);
    assert_eq!(carved.len(), 1);
    assert_eq!(carved[0].offset, base as usize);
    assert_eq!(carved[0].image.len(), 0x4000);
    assert_eq!(carved[0].streams[0].expanded, expanded);
    dump[base as usize + 0x2004 + compressed.len() - 1] ^= 1;
    assert!(carve_live_main(&dump).is_empty());
}

#[test]
fn resized_normal_requires_complete_declared_image() {
    let mut original = vec![0xff; 0x2000];
    original[..8].copy_from_slice(b"PIONEER ");
    original[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
    let template = DecodedEnvelope {
        image: original.clone(),
        info: EnvelopeInfo {
            model: "BDR-TEST".into(),
            revision: "1.00".into(),
            kind: ComponentKind::Normal,
            hardware_version: String::new(),
            kernel_version: String::new(),
            layout: Layout::Normal,
            payload_offset: 0x10200,
            payload_size: original.len(),
            declared_size: Some(original.len()),
            unknown_word_0x10: None,
            uniform_ranges: vec![],
            receiver_xor_policy: None,
        },
        header: vec![0; HEADER_LEN],
        prefix: vec![0; 0x10200 - HEADER_LEN],
        suffix: vec![],
        key: make_key(0x123456, 0x10000),
        xor_exceptions: Vec::new(),
        splices: Vec::new(),
    };
    let mut resized = original.clone();
    resized.extend([0xff; 0x100]);
    assert!(template.repack_resized_normal(&resized).is_none());
    resized[20..24].copy_from_slice(&0x2100u32.to_be_bytes());
    let envelope = template.repack_resized_normal(&resized).unwrap();
    assert_eq!(envelope.len(), 0x10200 + resized.len());
    assert_eq!(
        transform(&envelope[0x10200..], &template.key, false).unwrap(),
        resized
    );
    resized.push(0xff);
    assert!(template.repack_resized_normal(&resized).is_none());
}

#[test]
fn unsupported_header_is_metadata_only() {
    let mut envelope = vec![0xff; 0x100000];
    let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-107D\r\nRevision Level : 1.22\r\nFile Type : Normal\r\n";
    envelope[..banner.len()].copy_from_slice(banner);
    let header = header_info(&envelope).unwrap();
    assert_eq!(header.model, "DVR-107D");
    assert_eq!(header.revision, "1.22");
    assert_eq!(header.kind, Some(ComponentKind::Normal));
    assert!(decode_envelope(&envelope).is_none());
}

#[test]
fn plane_requires_a_direct_copy_layout_not_just_a_banner() {
    let mut envelope = vec![0xff; 0x20000];
    let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-112\r\nRevision Level : 1.28\r\nFile Type : Plane\r\n";
    envelope[..banner.len()].copy_from_slice(banner);
    envelope[0x8000..0x8004].copy_from_slice(&[0xf4, 0xf0, 0x27, 0xe3]);
    envelope[0x10000..0x10010].copy_from_slice(b"PIONEER  DVR-112");
    let decoded = decode_envelope(&envelope).unwrap();
    assert_eq!(decoded.info.layout, Layout::Plain);
    assert_eq!(decoded.repack(&decoded.image).unwrap(), envelope);

    let mut transformed = envelope.clone();
    transformed[0x10000..0x10008]
        .copy_from_slice(&[0x12, 0x1d, 0x9c, 0x8f, 0xbe, 0x4b, 0xcf, 0xec]);
    assert!(decode_envelope(&transformed).is_none());
    transformed = envelope;
    transformed[0x9000] = 0;
    assert!(decode_envelope(&transformed).is_none());
}

#[test]
fn transformed_plane_recovers_a_whitened_direct_copy_plane() {
    // Build the direct-copy Plane image the DVR-217 family carries, then
    // whiten the body from 0x200 with the fixed LCG keystream as the OEM
    // packer does. XOR is self-inverse, so the same pass produces the file.
    let mut plain = vec![0xffu8; 0x10010];
    let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-217\r\nRevision Level : 1.07\r\nFile Type : Plane\r\n";
    plain[..banner.len()].copy_from_slice(banner);
    plain[0x8000..0x8004].copy_from_slice(&[0x00, 0x55, 0x09, 0xfd]);
    plain[0x10000..0x10010].copy_from_slice(b"PIONEER  DVR-117");

    let mut envelope = plain[..PLANE_XOR_OFFSET].to_vec();
    envelope.extend(plane_lcg_xor(&plain[PLANE_XOR_OFFSET..]));
    // The whitened body must not look like a bare direct-copy Plane.
    assert!(!has_plain_image_layout(&envelope));

    let decoded = decode_envelope(&envelope).unwrap();
    assert_eq!(decoded.info.layout, Layout::TransformedPlane);
    assert_eq!(decoded.info.kind, ComponentKind::Plane);
    assert_eq!(decoded.info.model, "DVR-217");
    // The decoded image is the recovered direct-copy Plane body from 0x160.
    assert_eq!(decoded.image, plain[HEADER_LEN..]);
    assert_eq!(&decoded.image[0xfea0..0xfeb0], b"PIONEER  DVR-117");
    assert_eq!(decoded.repack(&decoded.image).unwrap(), envelope);

    // A single corrupted body word breaks the erased-gap check: the layout
    // is rejected rather than silently emitting a mis-whitened image.
    let mut broken = envelope.clone();
    broken[0x400] ^= 1;
    assert!(decode_envelope(&broken).is_none());
}
