use super::*;

fn kernel_file(derived: bool) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut image = vec![0u8; 0x10000];
    image[0xfe] = 1;
    image[0x1000..0x1008].copy_from_slice(b"SAT FFFF");
    let sum = image.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    image[0xfffc..].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    let mut file = vec![0u8; 0x200];
    let header = format!(
        "{}\r\nID : PIONEER TEST\r\nFile Type : Kernel\r\n",
        String::from_utf8_lossy(BANNER)
    );
    file[..header.len()].copy_from_slice(header.as_bytes());
    let seed = 0x123456;
    let key = make_key(seed, 0x1000);
    let encoded = transform(&image, &key, true).unwrap();
    if derived {
        file.extend(encoded);
        let state = jump_seed(seed, 0x11000, false);
        file.extend(make_key(state, 0x1000));
    } else {
        file.extend_from_slice(&key);
        file.extend(encoded);
    }
    (file, image, key)
}

// Independent receiver-word operation: do not validate encoding with the same
// transform routine used to produce it.
#[allow(clippy::manual_rotate)] // Independent arithmetic oracle for the production rotation.
fn receive(wire: &[u8]) -> Vec<u8> {
    let key = &wire[0x200..0x1200];
    let mut out = Vec::new();
    for (i, word) in wire[0x1200..].chunks_exact(4).enumerate() {
        let k = u32::from_le_bytes(key[(i * 4) % key.len()..][..4].try_into().unwrap());
        let v = u32::from_le_bytes(word.try_into().unwrap()) ^ k;
        let rotation = k & 31;
        let v = if rotation == 0 {
            v
        } else {
            (v >> rotation) | (v << (32 - rotation))
        };
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

#[test]
fn both_file_codecs_produce_the_same_receiver_representation() {
    let mut wires = Vec::new();
    for derived in [false, true] {
        let (file, image, key) = kernel_file(derived);
        let envelope = Envelope::load(&file).unwrap();
        assert_eq!(envelope.image, image);
        let wire = envelope.kernel_transfer_image().unwrap();
        assert_eq!(wire.len(), 0x11200);
        assert_eq!(&wire[..0x200], &file[..0x200]);
        assert_eq!(&wire[0x200..0x1200], key);
        assert_eq!(receive(&wire), image);
        assert_eq!(envelope.repack(&image).unwrap(), file);
        wires.push(wire);
    }
    assert_eq!(wires[0], wires[1]);
}

#[test]
fn derived_file_prefix_is_not_a_receiver_key() {
    let (file, image, _) = kernel_file(true);
    let mut wrong = file[..0x1200].to_vec();
    wrong.extend_from_slice(&file[0x200..0x10200]);
    let received = receive(&wrong);
    assert_ne!(received, image);
    assert!(received[..0x1000].iter().all(|&b| b == 0));
    assert_eq!(received[0xfe], 0);
}

#[test]
fn transfer_refuses_bad_checksum_and_unexpected_suffix() {
    let (mut file, _, _) = kernel_file(false);
    let mut envelope = Envelope::load(&file).unwrap();
    envelope.image[0x4000] ^= 1;
    assert!(envelope.kernel_transfer_image().is_none());
    file.extend_from_slice(&[0, 0, 0, 0]);
    assert!(Envelope::load(&file)
        .unwrap()
        .kernel_transfer_image()
        .is_none());
}

#[test]
fn transfer_encodes_the_current_image_after_valid_modification() {
    let (file, _, _) = kernel_file(true);
    let mut envelope = Envelope::load(&file).unwrap();
    envelope.image[0x2000..0x2004].copy_from_slice(&1u32.to_be_bytes());
    envelope.image[0x2004..0x2008].copy_from_slice(&u32::MAX.to_be_bytes());
    let wire = envelope.kernel_transfer_image().unwrap();
    assert_eq!(receive(&wire), envelope.image);
}

fn normal_receiver_kernel() -> DecodedEnvelope {
    let (file, _, _) = kernel_file(false);
    let mut kernel = Envelope::load(&file).unwrap();
    // A recognized policy with both exceptions beyond this synthetic image.
    kernel.image[0x3000..0x3014].copy_from_slice(&[
        0x7a, 0x20, 0, 0x10, 0, 0, 0x47, 12, 0x7a, 0x20, 0, 0x20, 0, 0, 0x47, 4, 0x01, 0xf0, 0x65,
        0x05,
    ]);
    kernel
}

fn signed_normal_files() -> (Vec<u8>, Vec<u8>) {
    let mut image = splice_tests::image();
    image[0x20..0x24].fill(0);
    let sum = image.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    });
    image[0x20..0x24].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    let mut continuous = splice_tests::envelope(&image, &[]);
    let mut scalar = [0; 20];
    scalar[19] = 5;
    signature::SigningKey::from_bytes(scalar)
        .unwrap()
        .sign_normal(&mut continuous)
        .unwrap();
    let mut spliced = splice_tests::envelope(&image, &[0xfe00, 0x2fe00, 0x3fe00]);
    spliced[..0x200].copy_from_slice(&continuous[..0x200]);
    (continuous, spliced)
}

#[test]
fn normal_transfer_removes_splices_and_restores_signed_representation() {
    let (continuous, spliced) = signed_normal_files();
    assert_eq!(
        signature::verify_normal_signature(&spliced),
        signature::SignatureCheck::Invalid
    );
    let kernel = normal_receiver_kernel();
    let decoded = decode_envelope_with_kernel(&spliced, &kernel).unwrap();
    assert_eq!(decoded.spliced_blocks().len(), 3);
    let wire = decoded.normal_transfer_image().unwrap();
    assert_eq!(wire, continuous);
    assert_eq!(
        signature::verify_normal_signature(&wire),
        signature::SignatureCheck::ValidKeyAndCiphertext
    );
    assert_eq!(decoded.repack(&decoded.image).unwrap(), spliced);
    assert_eq!(
        decode_envelope_with_kernel(&wire, &kernel).unwrap().image,
        decoded.image
    );
}

#[test]
fn normal_transfer_requires_policy_and_complete_valid_image() {
    let (continuous, spliced) = signed_normal_files();
    assert!(Envelope::load(&continuous)
        .unwrap()
        .normal_transfer_image()
        .is_none());
    let kernel = normal_receiver_kernel();
    let mut decoded = decode_envelope_with_kernel(&spliced, &kernel).unwrap();
    decoded.image[0x2000] ^= 1;
    assert!(decoded.normal_transfer_image().is_none());
    decoded.image[0x2000] ^= 1;
    decoded.image[0x1000..0x1004].copy_from_slice(b"BAD!");
    assert!(decoded.unrecovered_tail().is_some());
    assert!(decoded.normal_transfer_image().is_none());
    assert!(kernel.normal_transfer_image().is_none());
}

#[test]
fn continuous_normal_transfer_preserves_all_bytes() {
    let (continuous, _) = signed_normal_files();
    let decoded = decode_envelope_with_kernel(&continuous, &normal_receiver_kernel()).unwrap();
    assert!(decoded.spliced_blocks().is_empty());
    assert_eq!(decoded.normal_transfer_image().unwrap(), continuous);
}
