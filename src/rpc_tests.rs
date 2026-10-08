use super::*;
#[test]
fn read_only_command_and_known_response() {
    assert_eq!(report_key(), [0xa4, 0, 0, 0, 0, 0, 0, 0, 0, 8, 8, 0]);
    let state = State::parse(&[0, 6, 0, 0, 0x64, 0xfd, 1, 0]).unwrap();
    assert_eq!(
        state,
        State {
            type_code: 1,
            vendor_resets_remaining: 4,
            user_changes_remaining: 4,
            prohibited_regions: 0xfd,
            scheme: 1
        }
    );
    assert!(state.allows(2));
    for region in [0, 1, 3, 4, 5, 6, 7, 8, 9, 255] {
        assert!(!state.allows(region));
    }
}
#[test]
fn malformed_and_unset_are_not_invented_states() {
    assert!(State::parse(&[0; 7]).is_none());
    assert!(State::parse(&[0; 8]).is_none());
    let state = State::parse(&[0, 6, 0, 0, 0x25, 0xff, 1, 0]).unwrap();
    assert_eq!(state.user_changes_remaining, 5);
    assert!(!(1..=8).any(|r| state.allows(r)));
}
