use super::*;

use crate::comp_runtime::fixture;
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
    runtime::identify(&fixture(), 0x410000, &mut regions).unwrap();
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
        runtime::identify(&image, 0x410000, &mut regions).unwrap();
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
    assert_eq!(runtime::identify(&first, 0x410000, &mut regions), Err(2));
    assert!(regions.iter().all(|r| r.address.is_none()));
}
