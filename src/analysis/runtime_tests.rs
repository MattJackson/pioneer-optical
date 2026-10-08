use super::*;

fn fixture() -> Vec<u8> {
    let mut image = vec![0xff; 512];
    image[0x40..0x4e].copy_from_slice(&[
        1, 0, 0x6b, 0x20, 0, 0x41, 0x10, 0, 0x7a, 0x20, b'C', b'O', b'M', b'P',
    ]);
    image[0x60..0x80].copy_from_slice(&[
        0x0d, 0x39, 0x10, 0x19, 0x0d, 0x90, 0x0b, 0x50, 0x17, 0xf0, 0x10, 0x70, 0x7a, 0x05, 0,
        0x41, 0x10, 0, 0x0a, 0xd0, 1, 0, 0x69, 4, 0x0f, 0xc0, 0x0b, 0x90, 0, 0, 0, 0,
    ]);
    // Destination selectors and addresses deliberately differ from held images.
    image[0xa0..0xc4].copy_from_slice(&[
        0xa8, 0, 0x47, 0x1a, 0xa8, 1, 0x47, 0x0e, 0xa8, 2, 0x58, 0x60, 0, 0x70, 0x7a, 4, 0, 0xd0,
        0x30, 0, 0x40, 0x0e, 0x7a, 4, 0, 0xd0, 0x20, 0, 0x40, 6, 0x7a, 4, 0, 0xd0, 0x10, 0,
    ]);
    image[0xc4..0xc8].copy_from_slice(&[1, 0, 0x6f, 0xf5]);
    image[0xd0..0xd6].copy_from_slice(&[0x0f, 0xc0, 0x5e, 0x41, 0x20, 0]);
    image
}
fn regions() -> Vec<Region<'static>> {
    (0..3)
        .map(|id| Region {
            id,
            name: "Expanded".into(),
            stored: 0..0,
            address: None,
            address_source: None,
            metadata: Vec::new(),
            stream: Some(id),
            sha256: String::new(),
            size: 32,
            tables: Vec::new(),
            references: Vec::new(),
            bytes: Cow::Owned(vec![0; 32]),
        })
        .collect()
}
#[test]
fn loader_destinations_are_derived_and_not_assumed_by_stream_number() {
    let mut regions = regions();
    runtime::identify(&fixture(), 0x410000, &mut regions);
    assert_eq!(
        regions.iter().map(|r| r.address).collect::<Vec<_>>(),
        [Some(0xd01000), Some(0xd02000), Some(0xd03000)]
    );
    assert!(regions.iter().all(|r| r.address_source.is_some()));
}
#[test]
fn wrong_directory_broken_source_and_conflicting_loaders_do_not_get_mappings() {
    for offset in [0x44, 0x4a, 0x60, 0xa2, 0xc4, 0xd0] {
        let mut image = fixture();
        image[offset] ^= 0xff;
        let mut regions = regions();
        runtime::identify(&image, 0x410000, &mut regions);
        assert!(
            regions.iter().all(|r| r.address.is_none()),
            "offset {offset:x}"
        );
    }
    let mut first = fixture();
    let mut second = fixture();
    second[0xb1] = 0xd1; // Change stream 2's destination in a second loader.
    first.extend_from_slice(&second);
    let mut regions = regions();
    runtime::identify(&first, 0x410000, &mut regions);
    assert_eq!(regions[2].address, None);
}
