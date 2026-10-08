use super::*;

fn header(kind: &str, hardware: &str, destination: &str) -> Vec<u8> {
    let text = format!(
        "{}\r\nID : PIONEER TEST\r\nFile Type : {kind}\r\nHardware Version : {hardware}\r\nDestination : {destination}\r\n",
        String::from_utf8_lossy(BANNER)
    );
    let mut bytes = vec![0; HEADER_LEN];
    bytes[..text.len()].copy_from_slice(text.as_bytes());
    bytes
}

#[test]
fn zero_key_kernel_uses_structural_codec_independent_of_identity() {
    let mut image = vec![0; KERNEL_BODY_LEN];
    image[0x1000..0x1004].copy_from_slice(b"SAT ");
    for hardware in ["SAT 8A10", "SAT 8F00", "SAT FFFF"] {
        for destination in ["BACKUP", "GENERAL"] {
            let mut bytes = header("Kernel", hardware, destination);
            bytes.resize(0x1200, 0);
            bytes.extend_from_slice(&image);
            let decoded = decode_envelope(&bytes).unwrap();
            assert_eq!(decoded.info().layout, Layout::KernelFront);
            assert_eq!(decoded.image, image);
            assert_eq!(decoded.repack(&decoded.image).unwrap(), bytes);
        }
    }
}

#[test]
fn zero_key_normal_does_not_bypass_receiver_policy_for_backup_identity() {
    let mut image = vec![0; 0x2000];
    image[..8].copy_from_slice(b"PIONEER ");
    let length = image.len() as u32;
    image[20..24].copy_from_slice(&length.to_be_bytes());
    for hardware in ["SAT 8A10", "SAT 8F00", "SAT FFFF"] {
        let mut bytes = header("Normal", hardware, "BACKUP");
        bytes.resize(0x10200, 0);
        bytes.extend_from_slice(&image);
        let decoded = decode_envelope(&bytes).unwrap();
        assert_eq!(decoded.info().layout, Layout::Normal);
        assert_eq!(decoded.image, image);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), bytes);
        // A valid front-key envelope without a proven receiver XOR policy.
        let mut kernel_bytes = header("Kernel", hardware, "BACKUP");
        kernel_bytes.resize(0x11200, 0);
        kernel_bytes[0x2200..0x2204].copy_from_slice(b"SAT ");
        let kernel = decode_envelope(&kernel_bytes).unwrap();
        assert!(decode_envelope_with_kernel(&bytes, &kernel).is_none());
    }
}
