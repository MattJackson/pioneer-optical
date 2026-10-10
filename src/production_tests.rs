use super::*;

fn response(tag: &[u8], code: &[u8], factory: &[u8]) -> [u8; PARAMETERS_LEN] {
    let mut b = [0xff; PARAMETERS_LEN];
    b[TAG..TAG + tag.len()].copy_from_slice(tag);
    let mut padded = [b' '; PRODUCT_LEN];
    padded[..code.len()].copy_from_slice(code);
    b[PRODUCT..PRODUCT + PRODUCT_LEN].copy_from_slice(&padded);
    b[FACTORY..FACTORY + factory.len()].copy_from_slice(factory);
    b
}

// BDR-UD04 live capture: built as a BDR-UD03FAL, factory test 2017-08-03.
const UD04_FACTORY: &[u8] =
    b"011116505400B1500224178183-04+06+05+20251523A6637B+004+011+003+003102702902717080316602200";

#[test]
fn read_is_the_whole_a0_response() {
    assert_eq!(parameters(), [0x3c, 2, 0xa0, 0, 0, 0, 0, 8, 0, 0]);
}

#[test]
fn decodes_product_code_and_factory_date() {
    let b = response(b"kw01", b"BDR-UD03FAL", UD04_FACTORY);
    assert_eq!(
        parse(&b),
        Some(Production {
            product_code: "BDR-UD03FAL",
            manufactured: Some(Date {
                year: 2017,
                month: 8,
                day: 3
            }),
        })
    );
}

#[test]
fn missing_or_malformed_record_is_not_reported() {
    assert_eq!(parse(&[0xff; PARAMETERS_LEN]), None);
    assert_eq!(parse(&response(b"kw0x", b"BDR-212V", UD04_FACTORY)), None);
    assert_eq!(parse(&response(b"kw01", b"", UD04_FACTORY)), None);
    assert_eq!(
        parse(&response(b"kw01", b"BDR-212V", UD04_FACTORY)[..PRODUCT]),
        None
    );
}

#[test]
fn a_bad_factory_string_keeps_the_product_code() {
    let mut factory = UD04_FACTORY.to_vec();
    factory[FACTORY_DATE + 2..FACTORY_DATE + 4].copy_from_slice(b"13");
    let b = response(b"kw02", b"BDR-209XJB", &factory);
    let p = parse(&b).unwrap();
    assert_eq!((p.product_code, p.manufactured), ("BDR-209XJB", None));
    let b = response(b"kw02", b"BDR-209XJB", &[0xff; FACTORY_LEN]);
    assert_eq!(parse(&b).unwrap().manufactured, None);
}

#[test]
fn origin_follows_the_serial_suffix() {
    assert_eq!(origin("QHDL433450WL"), Some("China"));
    assert_eq!(origin("NFDL004706JP    "), Some("Japan"));
    assert_eq!(origin("ABCDEF123456XX"), None);
    assert_eq!(origin("J"), None);
}
