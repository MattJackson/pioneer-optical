use super::*;
#[test]
fn bounded_reads_keep_wire_addresses_separate_from_host_offsets() {
    assert_eq!(
        CPU_ALIAS.read_cdb(0, 0x300),
        Some(crate::cdb::read_memory(0x880000, 0x300))
    );
    assert!(CPU_HIGH.read_cdb(0x2000, 1).is_none());
    assert!(CPU_HIGH.read_cdb(0, 0x101).is_none());
    assert!(CPU_LOW.read_cdb(usize::MAX, 1).is_none());
    assert!(CPU_LOW.read_cdb(0, 0).is_none());
    assert_eq!(
        LOG.read_cdb(0, LOG.length),
        Some(crate::cdb::read_diagnostic_log())
    );
}

#[test]
fn rejects_a_surface_crossing_the_wire_address_limit() {
    let surface = ReadSurface {
        name: "test",
        selector: 0,
        offset: 0xffffff,
        length: 2,
        chunk: 2,
    };
    assert!(surface.read_cdb(0, 2).is_none());
    assert!(surface.read_cdb(0, 1).is_some());
}
