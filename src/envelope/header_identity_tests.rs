use super::*;
#[test]
fn generic_header_builder_recreates_literal_fixture() {
    let original = include_bytes!("../../tests/fixtures/id43.header");
    let info = header_info(original).unwrap();
    let opaque = HeaderOpaque {
        id_left_padding: 0,
        prevalidation: [0; 0x10],
        validation: [0; 0x50],
        extension: [0; 0x30],
        filename: [0; 0x10],
    };
    assert_eq!(&build_header(&info, &opaque).unwrap()[..0x160], original);
}

#[test]
fn literal_id43_id72_headers_preserve_independent_labels() {
    for (bytes, expected) in [
        (
            include_bytes!("../../tests/fixtures/id43.header").as_slice(),
            "ID43",
        ),
        (
            include_bytes!("../../tests/fixtures/id72.header").as_slice(),
            "ID72",
        ),
    ] {
        let h = header_info(bytes).unwrap();
        assert_eq!(h.kernel_version, expected);
        assert_eq!(h.destination, expected);
        assert_eq!(h.kernel_version2, "0000");
        assert!(!h.generated_date.is_empty());
    }
    let mut bytes = include_bytes!("../../tests/fixtures/id43.header").to_vec();
    let at = bytes.windows(4).rposition(|v| v == b"ID43").unwrap();
    bytes[at..at + 4].copy_from_slice(b"ID72");
    let h = header_info(&bytes).unwrap();
    assert_eq!(h.kernel_version, "ID43");
    assert_eq!(h.destination, "ID72");
    let mut missing = vec![0; 352];
    let h = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BDR-TEST\r\nKernel Version2 : 0000\r\n";
    missing[..h.len()].copy_from_slice(h);
    let h = header_info(&missing).unwrap();
    assert!(h.kernel_version.is_empty());
    assert!(h.destination.is_empty());
    assert!(h.generated_date.is_empty());
    assert_eq!(h.kernel_version2, "0000");
}
