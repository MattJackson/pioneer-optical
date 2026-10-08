use super::*;

#[test]
fn scaled_key_receiver_round_trip_when_configured() {
    let (Ok(kernel_path), Ok(normal_path)) = (
        std::env::var("PIONEER_SCALED_KERNEL_FIXTURE"),
        std::env::var("PIONEER_SCALED_NORMAL_FIXTURE"),
    ) else {
        return;
    };
    let kernel_bytes = std::fs::read(kernel_path).unwrap();
    let normal_bytes = std::fs::read(normal_path).unwrap();
    let kernel = decode_envelope(&kernel_bytes).unwrap();
    assert!(
        KernelXorPolicy::from_kernel(&kernel).is_some(),
        "receiver policy missing"
    );
    assert!(
        decode_envelope(&normal_bytes).is_some(),
        "Normal framing missing"
    );
    let normal = decode_envelope_with_kernel(&normal_bytes, &kernel).expect("receiver checksum");
    assert_eq!(normal.info.layout, Layout::NormalScaledKey);
    assert_eq!(normal.info.payload_offset, 0x200 + normal.image.len() / 16);
    assert!(be32_sum_zero(&normal.image));
    assert_eq!(normal.repack(&normal.image).unwrap(), normal_bytes);
    let mut damaged = normal_bytes.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(decode_envelope_with_kernel(&damaged, &kernel).is_none());
    assert!(
        decode_envelope_with_kernel(&normal_bytes[..normal_bytes.len() - 1], &kernel).is_none()
    );
}
fn branch(offsets: [u32; 2]) -> Vec<u8> {
    let mut b = vec![0x7a, 0x20];
    b.extend(offsets[0].to_be_bytes());
    b.extend([0x47, 12, 0x7a, 0x20]);
    b.extend(offsets[1].to_be_bytes());
    b.extend([0x47, 4, 1, 0xf0, 0x65, 5]);
    b.resize(64, 0);
    b
}
#[test]
fn xor_exception_retains_rotation_in_both_directions() {
    let key = 0x12345663u32.to_le_bytes();
    let plain = [0x87654321u32, 0x10203040, 0xaabbccdd]
        .map(u32::to_le_bytes)
        .concat();
    for reverse in [false, true] {
        let encoded = transform_with_policy(&plain, &key, true, reverse, &[4]).unwrap();
        let p = 0x10203040u32;
        let expected = if reverse {
            p.rotate_right(3)
        } else {
            p.rotate_left(3)
        };
        assert_eq!(&encoded[4..8], expected.to_le_bytes());
        assert_ne!(&encoded[4..8], &plain[4..8]);
        assert_eq!(
            transform_with_policy(&encoded, &key, false, reverse, &[4]).unwrap(),
            plain
        );
        assert_ne!(
            transform_with_rotation(&encoded, &key, false, reverse).unwrap(),
            plain
        );
    }
}
#[test]
fn exact_branch_recognizer_rejects_different_targets_and_non_xor() {
    let mut b = branch([0x16900, 0x77300]);
    assert_eq!(kernel_xor_branches(&b), vec![(0, [0x16900, 0x77300])]);
    b[7] = 10;
    assert!(kernel_xor_branches(&b).is_empty());
    b[7] = 12;
    b[18] = 0x64;
    assert!(kernel_xor_branches(&b).is_empty());
    assert!(kernel_xor_branches(&b[..15]).is_empty());
}
#[test]
fn policy_rejects_missing_ambiguous_unaligned_and_repeated_offsets() {
    let mut kernel = DecodedEnvelope {
        image: branch([0x16900, 0x77300]),
        info: EnvelopeInfo {
            model: "BDR-TEST".into(),
            revision: "1.00".into(),
            kind: ComponentKind::Kernel,
            hardware_version: String::new(),
            kernel_version: String::new(),
            layout: Layout::KernelFront,
            payload_offset: 0x1200,
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
    assert_eq!(
        KernelXorPolicy::from_kernel(&kernel).unwrap().offsets,
        [0x16900, 0x77300]
    );
    kernel.image.extend(branch([0x16900, 0x77300]));
    assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
    kernel.image = branch([0x16901, 0x77300]);
    assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
    kernel.image = branch([0x16900, 0x16900]);
    assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
    kernel.image = vec![0; 64];
    assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
}

#[test]
fn local_supplied_normal_matches_live_when_configured() {
    let Ok(dir) = std::env::var("PIONEER_CODEC_KAT_DIR") else {
        return;
    };
    let read = |name| std::fs::read(std::path::Path::new(&dir).join(name)).unwrap();
    let kernel_bytes = read("kernel.enc");
    let normal_bytes = read("normal.enc");
    let live = read("normal.live.bin");
    let kernel = decode_envelope(&kernel_bytes).unwrap();
    let policy = KernelXorPolicy::from_kernel(&kernel).unwrap();
    assert_eq!(policy.offsets, [0x16900, 0x77300]);
    let normal = decode_envelope_with_kernel(&normal_bytes, &kernel).unwrap();
    assert_eq!(normal.image.len(), 1864960);
    assert_eq!(
        sha(&normal.image),
        "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1"
    );
    assert_eq!(normal.image, live);
    assert_eq!(normal.repack(&live).unwrap(), normal_bytes);
    assert_eq!(
        sha(&normal_bytes),
        "8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141"
    );
    assert_ne!(decode_envelope(&normal_bytes).unwrap().image, live);
    assert!(KernelXorPolicy::from_kernel(&normal).is_none());
}
