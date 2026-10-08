use super::*;
use std::string::ToString;

#[test]
fn display_is_the_documented_text() {
    assert_eq!(
        Error::InvalidFilename.to_string(),
        "invalid embedded filename"
    );
    assert_eq!(
        Error::SelfVerification.to_string(),
        "self-signed envelope failed verification"
    );
    assert_eq!(
        Error::UnknownMarker { marker: 0x7 }.to_string(),
        "unrecognized generation marker 0x07"
    );
    assert!(Error::KernelBodySize { got: 5 }
        .to_string()
        .starts_with("Kernel body is 5 bytes, expected "));
}
