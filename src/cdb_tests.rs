#[test]
fn offset_and_length_use_all_24_bits() {
    assert_eq!(
        super::read_memory(0x12_3456, 0x65_4321)[3..9],
        [0x12, 0x34, 0x56, 0x65, 0x43, 0x21]
    );
    let t = super::transfer(crate::Role::Normal, 0x01_0203, 0x04_0506);
    assert_eq!(t[3..9], [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
}

use super::*;

#[test]
fn parameter_word_commands_are_bounded_and_use_native_mode() {
    assert_eq!(
        read_parameter_word(0x9f),
        Some([0x3c, 2, 0xa0, 0, 1, 0x3e, 0, 0, 2, 0])
    );
    assert_eq!(
        write_parameter_word(0x9f),
        Some([0x3b, 2, 0xa0, 0, 1, 0x3e, 0, 0, 2, 0])
    );
    assert!(read_parameter_word(0x3ff).is_some());
    assert!(write_parameter_word(0x3ff).is_some());
    for index in [0x400, 0xffff] {
        assert!(read_parameter_word(index).is_none());
        assert!(write_parameter_word(index).is_none());
    }
}

#[test]
fn bytes() {
    assert_eq!(inquiry(0x60), [0x12, 0, 0, 0, 0x60, 0]);
    assert_eq!(test_unit_ready(), [0; 6]);
    assert_eq!(request_sense(18), [0x03, 0, 0, 0, 18, 0]);
    assert_eq!(get_event_status(), [0x4A, 0, 0, 0, 0x10, 0, 0, 0, 0x08, 0]);
    assert_eq!(
        vendor_identity(),
        [0x3C, 0x02, 0xF1, 0, 0, 0, 0, 0, 0x30, 0]
    );
    assert_eq!(
        read_memory(0x1234, 0x1000),
        [0x3C, 0x02, 0xB0, 0, 0x12, 0x34, 0, 0x10, 0, 0]
    );
    assert_eq!(knock(), [0x3B, 0x02, 0x41, 0xA5, 0xAA, 0xAA, 0, 0, 0, 0]);
    assert_eq!(enter_update(), [0x3B, 0x04, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
    assert_eq!(
        transfer(Role::Kernel, 0, 0x80),
        [0x3B, 0x07, 0xFE, 0, 0, 0, 0, 0, 0x80, 0]
    );
    assert_eq!(
        transfer(Role::Normal, 0x8000, 0x80),
        [0x3B, 0x07, 0xF0, 0, 0x80, 0, 0, 0, 0x80, 0]
    );
    assert_eq!(finish(), [0x3B, 0x05, 0xFF, 0, 0, 0, 0, 0x01, 0, 0]);
    assert_eq!(dvr_arm(), [0x3B, 0x01, 0xF3, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(dvr_challenge(), [0x3C, 0x01, 0xF2, 0, 0, 0, 0, 0x04, 0, 0]);
    assert_eq!(dvr_response(), [0x3B, 0x01, 0xF2, 0, 0, 0, 0, 0x01, 0, 0]);
}
