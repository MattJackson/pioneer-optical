use super::*;

fn image() -> Vec<u8> {
    let mut bytes = b"PIONEER SAMPLE  ".to_vec();
    bytes.extend_from_slice(&[
        0x7a, 0x20, 0x9a, 0x78, 0x23, 0x61, 0x47, 8, 0x7a, 0x20, 1, 2, 3, 4, 0x46, 0x4e,
    ]);
    bytes
}

#[test]
fn control_contains_the_installed_descriptor_and_recovered_key_only() {
    let image = image();
    let receiver = Receiver::from_image(&image).unwrap();
    let control = receiver.entry_control(&image[..DESCRIPTOR_LEN]).unwrap();
    assert_eq!(&control[..DESCRIPTOR_LEN], &image[..DESCRIPTOR_LEN]);
    assert_eq!(&control[DESCRIPTOR_LEN..KEY_END], &[1, 2, 3, 4]);
    assert!(control[KEY_END..].iter().all(|&b| b == 0));
}

#[test]
fn live_mismatch_short_descriptor_and_unknown_handler_fail_closed() {
    let bytes = image();
    let receiver = Receiver::from_image(&bytes).unwrap();
    assert_eq!(
        receiver.entry_control(b"PIONEER OTHER   ").unwrap_err(),
        Error::DescriptorMismatch
    );
    assert_eq!(
        receiver
            .entry_control(&bytes[..DESCRIPTOR_LEN - 1])
            .unwrap_err(),
        Error::DescriptorMismatch
    );
    assert_eq!(
        Receiver::from_image(&bytes[..DESCRIPTOR_LEN]).unwrap_err(),
        Error::Unsupported
    );
    assert_eq!(
        Receiver::from_image(&[]).unwrap_err(),
        Error::InvalidDescriptor
    );
    let mut invalid = bytes;
    invalid[10] = 0xff;
    assert_eq!(
        Receiver::from_image(&invalid).unwrap_err(),
        Error::InvalidDescriptor
    );
}

#[test]
fn descriptor_only_control_has_no_fabricated_key() {
    let descriptor = *b"PIONEER SAMPLE  ";
    let control = Oem.control(&descriptor, ReceiverControl::DescriptorOnly);
    assert_eq!(&control[..DESCRIPTOR_LEN], &descriptor);
    assert!(control[DESCRIPTOR_LEN..].iter().all(|&b| b == 0));
}
