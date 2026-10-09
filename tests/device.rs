#![cfg(feature = "drive")]
use pioneer_optical::{
    device::{info::*, settings::*, Device, Error, WriteOutcome},
    drive::{Data, Transport},
};
use std::collections::VecDeque;

struct Mock {
    reads: VecDeque<Result<Vec<u8>, ()>>,
    calls: Vec<(Vec<u8>, Vec<u8>)>,
}
impl Mock {
    fn new(reads: Vec<Vec<u8>>) -> Self {
        Self {
            reads: reads.into_iter().map(Ok).collect(),
            calls: Vec::new(),
        }
    }
}
impl Transport for Mock {
    type Error = ();
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, ()> {
        match data {
            Data::In(b) => {
                self.calls.push((cdb.to_vec(), vec![]));
                let data = self.reads.pop_front().expect("unexpected read")?;
                let n = data.len().min(b.len());
                b[..n].copy_from_slice(&data[..n]);
                Ok(n)
            }
            Data::Out(b) => {
                self.calls.push((cdb.to_vec(), b.to_vec()));
                Ok(b.len())
            }
            Data::None => {
                self.calls.push((cdb.to_vec(), vec![]));
                Ok(0)
            }
        }
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        Some((5, 0x24, 0))
    }
}
fn status() -> Vec<u8> {
    let mut b = vec![0; 256];
    b[0..2].fill(255);
    b[2] = 2;
    b[4] = 1;
    b[5] = 8;
    b[9] = 1;
    b[43] = 1;
    b[45] = 1;
    b[49] = 4;
    b
}
#[test]
fn response_sentinels_and_unknown_modes_are_not_defaults() {
    assert!(F4Response::parse(&[0; 256]).is_none());
    assert!(F4Response::parse(&[255; 256]).is_none());
    assert!(F4Response::parse(&status()[..255]).is_none());
    let mut b = status();
    b[2] = 9;
    b[5] = 17;
    b[43] = 0;
    b[45] = 0;
    let s = F4Response::parse(&b).unwrap();
    assert_eq!(s.quiet_drive().current, Observed::Unknown(9));
    assert_eq!(s.quiet_drive().writable, Support::Unknown);
    assert_eq!(
        s.pure_read().supported().unwrap().current,
        Observed::Unknown(17)
    );
    b[2] = 255;
    b[4] = 255;
    b[9] = 0;
    let s = F4Response::parse(&b).unwrap();
    assert_eq!(s.quiet_drive().current, Observed::NotReported);
    assert_eq!(s.pure_read(), Capability::Unsupported);
}
#[test]
fn getters_are_read_only_and_do_not_cache_state() {
    let mut second = status();
    second[2] = 1;
    let mut t = Mock::new(vec![status(), second]);
    let mut d = Device::new(&mut t);
    assert_eq!(
        d.get(QuietDrive).unwrap().current,
        Observed::Known(QuietMode::Quiet)
    );
    assert_eq!(
        d.get(QuietDrive).unwrap().current,
        Observed::Known(QuietMode::Performance)
    );
    assert!(t
        .calls
        .iter()
        .all(|(c, b)| c == &[0x3c, 2, 0xf4, 0, 0, 0, 0, 1, 0, 0] && b.is_empty()));
}
#[test]
fn writes_require_positive_support_and_never_fall_back() {
    for flag in [0, 255] {
        let mut b = status();
        b[45] = flag;
        let mut t = Mock::new(vec![b]);
        assert!(Device::new(&mut t)
            .set(QuietDrive, QuietMode::Performance, Persistence::Saved)
            .is_err());
        assert_eq!(t.calls.len(), 1);
    }
    let mut t = Mock::new(vec![status()]);
    let value = PureReadValue {
        mode: PureReadMode::Perfect,
        real_time: true,
    };
    assert!(matches!(
        Device::new(&mut t).set(PureRead, value, Persistence::Volatile),
        Err(Error::Unsupported)
    ));
    assert_eq!(t.calls.len(), 1);
}
#[test]
fn persistence_and_persistent_quiet_are_independent() {
    for (policy, byte) in [(Persistence::Volatile, 0x83), (Persistence::Saved, 0xc3)] {
        let mut after = status();
        after[2] = 3;
        if policy == Persistence::Saved {
            after[3] = 3;
        }
        let mut t = Mock::new(vec![status(), after]);
        assert!(matches!(
            Device::new(&mut t).set(QuietDrive, QuietMode::PersistentQuiet, policy),
            Ok(WriteOutcome::Verified(_))
        ));
        assert_eq!(
            t.calls[1].0,
            [0xbb, 0, 255, 255, 255, 255, 0, 0, 0, 0, byte, 0]
        );
    }
}
#[test]
fn pureread_payload_readback_and_failed_verification() {
    let mut after = status();
    after[5] = 254;
    let mut t = Mock::new(vec![status(), after]);
    let value = PureReadValue {
        mode: PureReadMode::Perfect,
        real_time: false,
    };
    assert!(matches!(
        Device::new(&mut t).set(PureRead, value, Persistence::Saved),
        Ok(WriteOutcome::Verified(_))
    ));
    assert_eq!(t.calls[1].0, [0x3b, 1, 0xfa, 0, 0, 0, 0, 1, 0, 0]);
    assert_eq!(&t.calls[1].1[..7], &[1, 128, 1, 254, 1, 1, 0]);
    let mut t = Mock::new(vec![status()]);
    t.reads.push_back(Err(()));
    assert!(matches!(
        Device::new(&mut t).set(PureRead, value, Persistence::Volatile),
        Ok(WriteOutcome::Unverified(Error::Transport {
            sense: Some((5, 0x24, 0)),
            ..
        }))
    ));
    assert_eq!(t.calls.len(), 3);
}
#[test]
fn a_noop_does_not_consume_a_region_change() {
    let rpc = vec![0, 6, 0, 0, 0x60, 0xfd, 1, 0];
    let mut t = Mock::new(vec![rpc]);
    assert!(matches!(
        Device::new(&mut t).set(DvdRegion, Region::new(2).unwrap(), Persistent),
        Ok(WriteOutcome::Unchanged(_))
    ));
    assert_eq!(t.calls.len(), 1);
    assert!(Region::new(0).is_none());
    assert!(Region::new(9).is_none());
}
#[test]
fn exhausted_regions_are_not_written_and_valid_changes_are_verified() {
    let mut t = Mock::new(vec![vec![0, 6, 0, 0, 0x60, 0xfd, 1, 0]]);
    assert!(matches!(
        Device::new(&mut t).set(DvdRegion, Region::new(1).unwrap(), Persistent),
        Err(Error::RegionLocked)
    ));
    assert_eq!(t.calls.len(), 1);
    let mut t = Mock::new(vec![
        vec![0, 6, 0, 0, 0x64, 0xfd, 1, 0],
        vec![0, 6, 0, 0, 0x63, 0xfe, 1, 0],
    ]);
    assert!(matches!(
        Device::new(&mut t).set(DvdRegion, Region::new(1).unwrap(), Persistent),
        Ok(WriteOutcome::Verified(_))
    ));
    assert_eq!(
        t.calls[1],
        (
            vec![0xa3, 0, 0, 0, 0, 0, 0, 0, 0, 8, 6, 0],
            vec![0, 6, 0, 0, 0xfe, 0, 0, 0]
        )
    );
}
#[test]
fn feature_lengths_and_code_must_agree() {
    let b = [0, 0, 0, 12, 0, 0, 0, 0, 0, 1, 0, 4, 0, 0, 0, 7];
    for end in 0..b.len() {
        assert!(Feature::parse(&b[..end], 1).is_err());
    }
    assert_eq!(
        Feature::parse(&b, 1).unwrap().unwrap().payload(),
        &[0, 0, 0, 7]
    );
    assert!(Feature::parse(&b, 3).is_err());
    assert!(Feature::parse(&[0, 0, 0, 4, 0, 0, 0, 0], 1)
        .unwrap()
        .is_none());
    assert!(Feature::parse(&[0; 8], 1).is_err());
}
#[test]
fn mechanical_page_honors_block_descriptors_and_declared_length() {
    let mut b = vec![0; 32];
    b[1] = 30;
    b[7] = 8;
    b[16] = 0x2a;
    b[17] = 14;
    b[22] = 0x20;
    b[28] = 0x0f;
    b[29] = 0xa0;
    let m = Mechanical::parse(&b).unwrap();
    assert_eq!(m.buffer_kib(), Some(4000));
    assert_eq!(m.loader(), 1);
    for n in 0..b.len() {
        assert!(Mechanical::parse(&b[..n]).is_none());
    }
    b[16] = 0x6a;
    assert!(Mechanical::parse(&b).is_none());
}

#[test]
fn xd06_style_flags_do_not_require_the_unrelated_master_flag() {
    let mut b = status();
    b[43] = 0;
    b[45] = 1;
    let s = F4Response::parse(&b).unwrap();
    assert_eq!(s.quiet_drive().writable, Support::Supported);
    assert!(s.pure_read().supported().is_some());
    b[45] = 0;
    assert_eq!(
        F4Response::parse(&b).unwrap().quiet_drive().writable,
        Support::Unknown
    );
}
#[test]
fn saved_quiet_is_not_assumed_to_match_current_quiet() {
    let mut b = status();
    b[2] = 1;
    b[3] = 2;
    let s = F4Response::parse(&b).unwrap().quiet_drive();
    assert_eq!(s.current, Observed::Known(QuietMode::Performance));
    assert_eq!(s.saved, Observed::Known(QuietMode::Quiet));
}
#[test]
fn snapshot_keeps_identity_when_optional_queries_fail_and_never_writes() {
    let mut inquiry = vec![0; 96];
    inquiry[0] = 5;
    inquiry[4] = 91;
    inquiry[8..16].copy_from_slice(b"PIONEER ");
    inquiry[16..32].copy_from_slice(b"BD-RW  BDR-XD08U");
    let mut t = Mock::new(vec![inquiry]);
    for _ in 0..18 {
        t.reads.push_back(Err(()));
    }
    let s = Device::new(&mut t).snapshot();
    assert_eq!(s.information.inquiry.unwrap().vendor(), "PIONEER");
    assert!(s.information.pioneer.is_err());
    assert!(s.settings.is_err());
    assert!(s.dvd_region.is_err());
    assert_eq!(t.calls.len(), 19);
    assert!(t
        .calls
        .iter()
        .all(|(c, b)| [0x12, 0x3c, 0x46, 0x5a, 0xa4].contains(&c[0]) && b.is_empty()));
}

#[test]
fn unsupported_parent_hides_version_and_unknown_is_distinct() {
    let mut b = status();
    b[9] = 0;
    b[29] = 1;
    b[49] = 4;
    assert_eq!(
        F4Response::parse(&b).unwrap().pure_read(),
        Capability::Unsupported
    );
    b[9] = 2;
    assert_eq!(
        F4Response::parse(&b).unwrap().pure_read(),
        Capability::Unknown
    );
    b[9] = 1;
    b[29] = 0;
    b[28] = 1;
    let state = F4Response::parse(&b).unwrap().pure_read();
    assert_eq!(
        state.supported().unwrap().real_time,
        Capability::Unsupported
    );
    assert_eq!(state.supported().unwrap().version, Some(4));
}

#[test]
fn alternate_codec_owns_query_layout_and_defaults_to_read_only() {
    struct Alternate;
    impl Codec for Alternate {
        fn query(&self) -> Result<Command, CodecError> {
            Command::read(&[0xc0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 512)
        }
        fn decode(&self, response: &[u8]) -> Result<Settings, CodecError> {
            if response.len() != 512 || response[400] != 42 {
                return Err(CodecError::Malformed);
            }
            Ok(Settings {
                quiet: QuietState {
                    current: Observed::Known(QuietMode::Performance),
                    saved: Observed::Known(QuietMode::Quiet),
                    writable: Support::Supported,
                },
                pure: Capability::Unsupported,
                controls: Controls::default(),
            })
        }
    }
    let mut response = vec![0; 512];
    response[400] = 42;
    let mut t = Mock::new(vec![response.clone(), response]);
    let mut d = Device::with_settings_codec(&mut t, &Alternate);
    let settings = d.settings().unwrap();
    let entries: Vec<_> = settings.entries().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].current,
        Observed::Known(Value::Quiet(QuietMode::Performance))
    );
    assert_eq!(entries[0].control.writable, Support::Unsupported);
    assert!(matches!(
        d.set(QuietDrive, QuietMode::Quiet, Persistence::Saved),
        Err(Error::Unsupported)
    ));
    assert_eq!(t.calls.len(), 2);
    assert!(t
        .calls
        .iter()
        .all(|(c, data)| c.len() == 12 && c[0] == 0xc0 && data.is_empty()));
}

#[test]
fn descriptors_hide_unsupported_children_and_keep_persistence_explicit() {
    let mut response = status();
    response[9] = 0;
    response[49] = 4;
    let state = VendorF4.decode(&response).unwrap();
    let entries: Vec<_> = state.entries().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, SettingId::QuietDrive);
    assert_eq!(entries[0].control.choices.len(), 4);
    assert!(entries[0].control.persistence.saved);
    assert!(entries[0].control.persistence.volatile);
    response[9] = 1;
    let state = VendorF4.decode(&response).unwrap();
    let entries: Vec<_> = state.entries().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].id, SettingId::PureRead);
    assert_eq!(entries[1].version, Some(4));
    assert_eq!(entries[1].control.choices.len(), 3);
    assert_eq!(entries[1].saved, Observed::NotReported);
}

#[test]
fn bounded_codec_commands_reject_invalid_shapes() {
    assert!(Command::new(&[]).is_err());
    assert!(Command::new(&[0; 17]).is_err());
    assert!(Command::read(&[0x3c; 10], 0).is_err());
    assert!(Command::read(&[0x3c; 10], 4097).is_err());
    assert!(Command::write(&[0x3b; 10], &[0; 257]).is_err());
}

#[test]
fn legacy_feature_prefix_is_not_mistaken_for_a_missing_f4_signature() {
    // SAT 8221 F4 builder: bytes 0/1 are runtime and saved feature flags,
    // 2/3 remain active/saved Quiet modes; 9 advertises PureRead.
    let mut response = status();
    response[11..15].fill(255);
    for prefix in [[0, 0], [0, 1], [1, 0], [1, 1], [255, 1]] {
        response[..2].copy_from_slice(&prefix);
        let state = VendorF4.decode(&response).unwrap();
        assert_eq!(state.quiet.current, Observed::Known(QuietMode::Quiet));
        assert!(matches!(state.pure, Capability::Supported(_)));
    }
    response[0] = 42;
    assert!(VendorF4.decode(&response).is_err());
    response.fill(0);
    assert!(VendorF4.decode(&response).is_err());
}

#[test]
fn saved_quiet_readback_cannot_contradict_requested_startup_mode() {
    let mut after = status();
    after[2] = 1;
    after[3] = 2;
    let mut transport = Mock::new(vec![status(), after]);
    assert!(matches!(
        Device::new(&mut transport).set(QuietDrive, QuietMode::Performance, Persistence::Saved),
        Ok(WriteOutcome::Mismatch(_))
    ));
    assert_eq!(transport.calls.len(), 3);
}

#[test]
fn pure_read_cannot_disable_a_read_only_or_unknown_extension() {
    struct Restricted;
    impl Codec for Restricted {
        fn query(&self) -> Result<Command, CodecError> {
            VendorF4.query()
        }
        fn decode(&self, b: &[u8]) -> Result<Settings, CodecError> {
            VendorF4.decode(b)
        }
        fn controls(&self, s: &Settings) -> Controls {
            let mut controls = VendorF4.controls(s);
            controls.real_time = Control::default();
            controls
        }
        fn pure_read_write(&self, _: PureReadValue, _: Persistence) -> Result<Command, CodecError> {
            panic!("read-only extension must not reach encoder")
        }
    }
    let mut before = status();
    before[29] = 1;
    before[28] = 1;
    let mut transport = Mock::new(vec![before]);
    let requested = PureReadValue {
        mode: PureReadMode::Perfect,
        real_time: false,
    };
    assert!(matches!(
        Device::with_settings_codec(&mut transport, &Restricted).set(
            PureRead,
            requested,
            Persistence::Volatile
        ),
        Err(Error::Unsupported)
    ));
    assert_eq!(transport.calls.len(), 1);
    let mut before = status();
    before[29] = 255;
    let mut transport = Mock::new(vec![before]);
    assert!(matches!(
        Device::new(&mut transport).set(PureRead, requested, Persistence::Volatile),
        Err(Error::NotReported)
    ));
    assert_eq!(transport.calls.len(), 1);
}

#[test]
fn parser_boundaries_preserve_unknowns_and_never_panic() {
    let block = status();
    for len in 0..256 {
        assert!(F4Response::parse(&block[..len]).is_none());
    }
    for value in 0..=255u8 {
        let mut b = block.clone();
        b[2] = value;
        b[3] = value;
        b[9] = value;
        b[29] = value;
        let state = VendorF4.decode(&b).unwrap();
        if value > 3 && value != 255 {
            assert_eq!(state.quiet.current, Observed::Unknown(value));
        }
        if value != 0 && value != 1 {
            assert_eq!(state.pure, Capability::Unknown);
        }
    }
    let mut seed = 0x12345678u32;
    for len in 0..=512 {
        let mut bytes = vec![0; len];
        for b in &mut bytes {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (seed >> 24) as u8;
        }
        let _ = F4Response::parse(&bytes);
        let _ = Inquiry::parse(&bytes);
        let _ = Feature::parse(&bytes, 0x40);
        let _ = Mechanical::parse(&bytes);
    }
}

#[test]
fn oversized_transport_counts_are_rejected_before_decoding() {
    struct Overreport;
    impl Transport for Overreport {
        type Error = ();
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, _: &[u8], data: Data<'_>) -> Result<usize, ()> {
            match data {
                Data::In(b) => Ok(b.len() + 1),
                _ => panic!("read-only test"),
            }
        }
    }
    assert!(matches!(
        Device::new(&mut Overreport).settings(),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        Device::new(&mut Overreport).get(DvdRegion),
        Err(Error::Malformed)
    ));
    assert!(matches!(
        Device::new(&mut Overreport).feature(0x40),
        Err(Error::Malformed)
    ));
}

#[test]
fn partial_oversized_and_failed_writes_are_never_retried_or_verified() {
    struct Fault {
        inner: Mock,
        result: Result<usize, ()>,
    }
    impl Transport for Fault {
        type Error = ();
        fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, ()> {
            let writing = matches!(&data, Data::Out(_));
            let n = self.inner.exec(cdb, data)?;
            if writing {
                self.result
            } else {
                Ok(n)
            }
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            Some((5, 0x24, 0))
        }
    }
    for result in [Ok(0), Ok(255), Ok(257), Err(())] {
        let mut t = Fault {
            inner: Mock::new(vec![status()]),
            result,
        };
        let outcome = Device::new(&mut t).set(
            PureRead,
            PureReadValue {
                mode: PureReadMode::Perfect,
                real_time: false,
            },
            Persistence::Volatile,
        );
        match result {
            Ok(_) => assert!(matches!(
                outcome,
                Ok(WriteOutcome::Unverified(Error::Malformed))
            )),
            Err(_) => assert!(matches!(outcome, Err(Error::Transport { .. }))),
        }
        assert_eq!(t.inner.calls.len(), 2);
    }
}

#[test]
fn codec_command_direction_is_checked_before_io() {
    struct WrongDirection {
        query: bool,
    }
    impl Codec for WrongDirection {
        fn query(&self) -> Result<Command, CodecError> {
            if self.query {
                Command::write(&[0xc0], &[1])
            } else {
                VendorF4.query()
            }
        }
        fn decode(&self, b: &[u8]) -> Result<Settings, CodecError> {
            VendorF4.decode(b)
        }
        fn controls(&self, s: &Settings) -> Controls {
            VendorF4.controls(s)
        }
        fn quiet_write(&self, _: QuietMode, _: Persistence) -> Result<Command, CodecError> {
            Command::read(&[0xc1], 32)
        }
    }
    let mut t = Mock::new(vec![]);
    assert!(matches!(
        Device::with_settings_codec(&mut t, &WrongDirection { query: true }).settings(),
        Err(Error::InvalidValue)
    ));
    assert!(t.calls.is_empty());
    let mut t = Mock::new(vec![status()]);
    assert!(matches!(
        Device::with_settings_codec(&mut t, &WrongDirection { query: false }).set(
            QuietDrive,
            QuietMode::Performance,
            Persistence::Volatile
        ),
        Err(Error::InvalidValue)
    ));
    assert_eq!(t.calls.len(), 1);
}

#[test]
fn unchanged_realtime_still_honors_saved_policy_restrictions() {
    struct VolatileRealtime;
    impl Codec for VolatileRealtime {
        fn query(&self) -> Result<Command, CodecError> {
            VendorF4.query()
        }
        fn decode(&self, b: &[u8]) -> Result<Settings, CodecError> {
            VendorF4.decode(b)
        }
        fn controls(&self, s: &Settings) -> Controls {
            let mut controls = VendorF4.controls(s);
            controls.real_time.persistence.saved = false;
            controls
        }
        fn pure_read_write(&self, _: PureReadValue, _: Persistence) -> Result<Command, CodecError> {
            panic!("unsupported persistence must not reach encoder")
        }
    }
    let mut before = status();
    before[29] = 1;
    before[28] = 0;
    let mut transport = Mock::new(vec![before]);
    let value = PureReadValue {
        mode: PureReadMode::Perfect,
        real_time: false,
    };
    assert!(matches!(
        Device::with_settings_codec(&mut transport, &VolatileRealtime).set(
            PureRead,
            value,
            Persistence::Saved
        ),
        Err(Error::InvalidValue)
    ));
    assert_eq!(transport.calls.len(), 1);
}
