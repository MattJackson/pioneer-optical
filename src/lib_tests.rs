use super::*;

fn inquiry(product: &[u8; 16]) -> [u8; INQUIRY_LEN] {
    let mut b = [b' '; INQUIRY_LEN];
    b[0] = 0x05;
    b[8..15].copy_from_slice(b"PIONEER");
    b[16..32].copy_from_slice(product);
    b[32..36].copy_from_slice(b"1.14");
    b
}

fn vendor(platform: &[u8; 8]) -> [u8; IDENTITY_LEN] {
    let mut b = [b' '; IDENTITY_LEN];
    b[0..12].copy_from_slice(b"QHDL433450WL");
    b[16..24].copy_from_slice(platform);
    b[24..28].copy_from_slice(b"ID40");
    b[32..36].copy_from_slice(b"ID41");
    b[40..44].copy_from_slice(b"0000");
    b
}

#[test]
fn identity_fields() {
    let id = Identity::parse(&inquiry(b"BD-RW   BDR-UD04"), &vendor(b"SAT 8A10")).unwrap();
    assert_eq!(id.device_type(), 5);
    assert_eq!(id.vendor(), "PIONEER");
    assert_eq!(id.product(), "BD-RW   BDR-UD04");
    assert_eq!(id.revision(), "1.14");
    assert_eq!(id.serial(), "QHDL433450WL");
    assert_eq!(id.platform(), "SAT 8A10");
    assert_eq!(id.kernel_tag(), "ID40");
    assert_eq!(id.normal_tag(), "ID41");
    assert_eq!(id.code(), "0000");
    assert_eq!(id.class(), Some(DriveClass::Bd));
}

#[test]
fn component_kind_conversions() {
    assert_eq!(ComponentKind::from(Role::Kernel), ComponentKind::Kernel);
    assert_eq!(ComponentKind::from(Role::Normal), ComponentKind::Normal);
    assert_eq!(Role::try_from(ComponentKind::Kernel), Ok(Role::Kernel));
    assert_eq!(Role::try_from(ComponentKind::Normal), Ok(Role::Normal));
    assert_eq!(
        Role::try_from(ComponentKind::Plane),
        Err(ComponentKind::Plane)
    );
    for kind in [
        ComponentKind::Kernel,
        ComponentKind::Normal,
        ComponentKind::Plane,
    ] {
        assert_eq!(ComponentKind::from_header(kind.as_str()), Some(kind));
    }
    assert_eq!(ComponentKind::from_header("Other"), None);
}

#[test]
fn identity_class_and_bounds() {
    let dvr = Identity::parse(&inquiry(b"DVD-RW  DVR-112D"), &vendor(b"DVR 0112")).unwrap();
    assert_eq!(dvr.class(), Some(DriveClass::Dvr));
    let other = Identity::parse(&inquiry(b"CD-RW   UNKNOWN1"), &vendor(b"SAT 8A10")).unwrap();
    assert_eq!(other.class(), None);
    // The class needs both the product family and the platform.
    let dvd_sat = Identity::parse(&inquiry(b"DVD-RW  DVR-112D"), &vendor(b"SAT 8A10")).unwrap();
    assert_eq!(dvd_sat.class(), None);
    let bd_dvr = Identity::parse(&inquiry(b"BD-RW   BDR-UD04"), &vendor(b"DVR 0112")).unwrap();
    assert_eq!(bd_dvr.class(), Some(DriveClass::Bd));
    assert!(Identity::parse(&[0; 35], &[0; 48]).is_none());
    assert!(Identity::parse(&[0; 36], &[0; 43]).is_none());
    assert!(Identity::parse(&[0; 36], &[0; 44]).is_some());
}

#[test]
fn raw_blocks_are_the_parsed_bytes() {
    let inq = inquiry(b"BD-RW   BDR-UD04");
    let ven = vendor(b"SAT 8A10");
    let id = Identity::parse(&inq, &ven).unwrap();
    assert_eq!(id.inquiry_bytes(), &inq);
    assert_eq!(id.vendor_bytes(), &ven);
}

#[test]
fn class_requires_a_known_product_family() {
    let id = Identity::parse(&inquiry(b"CD-RW   UNKNOWN1"), &vendor(b"DVR 0112")).unwrap();
    assert_eq!(id.class(), None);
}

#[test]
fn locked_sense_needs_key_and_code() {
    assert!(sense::is_locked(0x05, 0x24, 0x00));
    assert!(!sense::is_locked(0x05, 0x24, 0x01));
    assert!(!sense::is_locked(0x05, 0x25, 0x00));
    assert!(!sense::is_locked(0x02, 0x24, 0x00));
    assert!(!sense::is_locked(0x00, 0x00, 0x00));
}

#[cfg(feature = "std")]
#[test]
fn component_kind_displays_its_header_text() {
    use std::string::ToString;
    assert_eq!(ComponentKind::Kernel.to_string(), "Kernel");
    assert_eq!(ComponentKind::Normal.to_string(), "Normal");
    assert_eq!(ComponentKind::Plane.to_string(), "Plane");
}
