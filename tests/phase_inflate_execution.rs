//! Actual captured original/recompressed streams exercised by the production validator.
#![cfg(feature = "envelope")]
const BASE: u32 = 0x410000;
#[test]
fn native_inflater_executes_original_and_recompressed_streams() {
    use pioneer_optical::filters::phase::{
        bundle::waveforms::resources::native_comp, native::arithmetic,
    };
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-inflate/manifest.json")).unwrap();
    let mut normal = vec![0xff; (0x5f0100 - BASE) as usize];
    let regions: &[(u32,&[u8])]=&[
        (0x57cc18,include_bytes!("../src/filters/phase/bundle/waveforms/resources/native_comp/adler_combine.bin")),
        (0x57ae64,include_bytes!("../src/filters/phase/bundle/waveforms/resources/native_comp/wrapper_and_inflate.bin")),
        (0x57ccd0,include_bytes!("../src/filters/phase/bundle/waveforms/resources/native_comp/fast_and_tables.bin")),
        (0x57deae,include_bytes!("../src/filters/phase/bundle/waveforms/resources/native_comp/shifts.bin")),
        (0x5abd02,include_bytes!("../src/filters/phase/bundle/waveforms/resources/native_comp/constants.bin")),
        (0x54b724,include_bytes!("../src/filters/phase/bundle/waveforms/resources/native_comp/loader.bin")),
    ];
    for &(address, bytes) in regions {
        let at = (address - BASE) as usize;
        normal[at..at + bytes.len()].copy_from_slice(bytes);
    }
    let captured = include_bytes!("fixtures/phase-inflate/arithmetic.bin");
    let mut source = vec![0xff; 0x220000];
    let offsets: Vec<_> = manifest["arithmetic_offsets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as usize)
        .collect();
    let mut at = 0;
    for (offset, len) in offsets.iter().zip([24, 38, 64]) {
        source[*offset..*offset + len].copy_from_slice(&captured[at..at + len]);
        at += len;
    }
    let bound = arithmetic::observe(
        &source,
        BASE,
        BASE + offsets[0] as u32,
        BASE + offsets[1] as u32,
    )
    .unwrap();
    let spans = [bound.multiply, bound.signed_divide, bound.unsigned_divide];
    let positions = [0x5f0000, 0x5f0020, 0x5f0050];
    for (range, to) in spans.iter().zip(positions) {
        normal[(to - BASE) as usize..(to - BASE) as usize + range.len()]
            .copy_from_slice(&source[range.clone()]);
    }
    normal[(positions[1] - BASE) as usize + 19..(positions[1] - BASE) as usize + 22]
        .copy_from_slice(&positions[2].to_be_bytes()[1..]);
    let originals: [&[u8]; 6] = [
        include_bytes!("fixtures/phase-inflate/original-0.zlib"),
        include_bytes!("fixtures/phase-inflate/original-1.zlib"),
        include_bytes!("fixtures/phase-inflate/original-2.zlib"),
        include_bytes!("fixtures/phase-inflate/original-3.zlib"),
        include_bytes!("fixtures/phase-inflate/original-4.zlib"),
        include_bytes!("fixtures/phase-inflate/original-5.zlib"),
    ];
    let recompressed: [&[u8]; 6] = [
        include_bytes!("fixtures/phase-inflate/recompressed-0.zlib"),
        include_bytes!("fixtures/phase-inflate/recompressed-1.zlib"),
        include_bytes!("fixtures/phase-inflate/recompressed-2.zlib"),
        include_bytes!("fixtures/phase-inflate/recompressed-3.zlib"),
        include_bytes!("fixtures/phase-inflate/recompressed-4.zlib"),
        include_bytes!("fixtures/phase-inflate/recompressed-5.zlib"),
    ];

    normal[0x1000..0x1004].copy_from_slice(b"COMP");
    for (index, compressed) in originals.iter().enumerate() {
        let stream = &manifest["streams"][index];
        let start = stream["start"].as_u64().unwrap() as usize;
        let expanded = stream["expanded"].as_u64().unwrap() as u32;
        normal[start..start + 4].copy_from_slice(&expanded.to_be_bytes());
        normal[start + 4..start + 4 + compressed.len()].copy_from_slice(compressed);
        normal[0x1004 + index * 8..0x1008 + index * 8]
            .copy_from_slice(&(BASE + start as u32).to_be_bytes());
        normal[0x1008 + index * 8..0x100c + index * 8]
            .copy_from_slice(&(BASE + start as u32 + compressed.len() as u32).to_be_bytes());
    }
    let binding = native_comp::observe(&normal).unwrap();
    let mut changed = native_comp::retarget_arithmetic(&normal, positions).unwrap();
    for (index, compressed) in recompressed.iter().enumerate() {
        let start = manifest["streams"][index]["start"].as_u64().unwrap() as usize;
        assert!(compressed.len() < originals[index].len());
        changed[start + 4..start + 4 + originals[index].len()].fill(0xff);
        changed[start + 4..start + 4 + compressed.len()].copy_from_slice(compressed);
        changed[0x1008 + index * 8..0x100c + index * 8]
            .copy_from_slice(&(BASE + start as u32 + compressed.len() as u32).to_be_bytes());
    }
    assert_eq!(
        native_comp::execution::validate(&normal, &changed, &binding, positions),
        Some(())
    );
    let mut bad = changed.clone();
    bad[binding.calls[0].offset + 3] ^= 1;
    assert_eq!(
        native_comp::execution::validate(&normal, &bad, &binding, positions),
        None,
        "unbound call target"
    );
    let mut bad = changed.clone();
    bad[(positions[0] - BASE) as usize] ^= 1;
    assert_eq!(
        native_comp::execution::validate(&normal, &bad, &binding, positions),
        None,
        "unbound arithmetic"
    );
    let mut bad = changed.clone();
    let first = manifest["streams"][0]["start"].as_u64().unwrap() as usize;
    bad[first + 8] ^= 1;
    assert_eq!(
        native_comp::execution::validate(&normal, &bad, &binding, positions),
        None,
        "corrupt actual stream"
    );
    let mut bad_binding = binding.clone();
    bad_binding.entry += 2;
    assert_eq!(
        native_comp::execution::validate(&normal, &changed, &bad_binding, positions),
        None,
        "unbound caller-supplied evidence"
    );
}
