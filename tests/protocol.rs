use pioneer_optical::protocol::{Evidence, State};
fn inquiry() -> [u8; 36] {
    let mut b = [b' '; 36];
    b[0] = 5;
    b[8..16].copy_from_slice(b"ASUS    ");
    b[16..32].copy_from_slice(b"SBC-06D2X-U     ");
    b[32..36].copy_from_slice(b"1.10");
    b
}
fn vendor() -> [u8; 48] {
    let mut b = [b' '; 48];
    b[..12].copy_from_slice(b"LJDL050094WL");
    b[16..24].copy_from_slice(b"SAT 8591");
    b[24..28].copy_from_slice(b"ID22");
    b[32..36].copy_from_slice(b"ID22");
    b[40..44].copy_from_slice(b"0000");
    b
}
#[test]
fn asus_protocol_is_independent_of_brand() {
    for name in [b"ASUS    ", b"PIONEER ", b"Slimtype", b"ACME    "] {
        let mut i = inquiry();
        i[8..16].copy_from_slice(name);
        let e = Evidence::parse(&i, &vendor()).unwrap().unwrap();
        assert_eq!(e.identity().platform(), "SAT 8591");
        assert_eq!(e.state(), State::Normal);
    }
}
#[test]
fn loader_does_not_need_serial_or_normal_tag() {
    let mut i = inquiry();
    i[32..36].copy_from_slice(b"0000");
    let mut v = vendor();
    v[..16].fill(b' ');
    v[32..40].fill(b' ');
    assert_eq!(
        Evidence::parse(&i, &v).unwrap().unwrap().state(),
        State::Loader
    );
}
#[test]
fn reject_incomplete_binary_echo_and_non_optical() {
    assert!(Evidence::parse(&inquiry(), &vendor()[..40]).is_err());
    for v in [[0; 48], [255; 48]] {
        assert!(Evidence::parse(&inquiry(), &v).unwrap().is_none());
    }
    let mut i = inquiry();
    i[0] = 0;
    assert!(Evidence::parse(&i, &vendor()).unwrap().is_none());
    let mut v = vendor();
    v[18] = 0xff;
    assert!(Evidence::parse(&inquiry(), &v).unwrap().is_none());
}
#[test]
fn unknown_platform_is_evidence_without_writer_permission() {
    let mut v = vendor();
    v[16..24].copy_from_slice(b"NEW 1234");
    let e = Evidence::parse(&inquiry(), &v).unwrap().unwrap();
    assert_eq!(e.identity().platform(), "NEW 1234");
}

#[test]
fn shared_response_preserves_metadata_and_matches_without_platform_allowlist() {
    use pioneer_optical::protocol::Response;
    for hardware in [
        b"SAT 8591",
        b"REC 8C00",
        b"NEW 1234",
        b"SCSI0001",
        b"ATA 0009",
    ] {
        let mut v = vendor();
        v[16..24].copy_from_slice(hardware);
        let parsed = Response::parse(&inquiry(), &v).unwrap();
        let identity = parsed.identity().clone();
        assert_eq!(parsed.into_evidence().unwrap().identity(), &identity);
        assert_eq!(identity.platform().as_bytes(), hardware);
    }
    let mut v = vendor();
    v[24..32].fill(b' ');
    let parsed = Response::parse(&inquiry(), &v).unwrap();
    assert_eq!(parsed.identity().platform(), "SAT 8591");
    assert!(parsed.into_evidence().is_none());
}
