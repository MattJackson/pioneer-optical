extern crate std;
use super::*;
use std::{vec, vec::Vec};

#[derive(Default)]
struct Clock {
    now: Duration,
    sleeps: Vec<Duration>,
    progress: Vec<(Role, usize, usize)>,
    failures: usize,
}
impl UpdateRuntime for Clock {
    fn elapsed(&self) -> Duration {
        self.now
    }
    fn sleep(&mut self, delay: Duration) {
        self.now += delay;
        self.sleeps.push(delay);
    }
    fn progress(&mut self, role: Role, written: usize, total: usize) {
        self.progress.push((role, written, total));
    }
    fn poll_failed(&mut self, _: Duration, _: &dyn core::fmt::Debug) {
        self.failures += 1;
    }
}

struct Mock {
    calls: Vec<(Vec<u8>, Vec<u8>)>,
    revision: [u8; 4],
    short: bool,
    fail_write: Option<usize>,
    writes: usize,
    busy: usize,
    fail_event: bool,
}
impl Default for Mock {
    fn default() -> Self {
        Self {
            calls: Vec::new(),
            revision: *b"000 ",
            short: false,
            fail_write: None,
            writes: 0,
            busy: 0,
            fail_event: false,
        }
    }
}
impl Transport for Mock {
    type Error = &'static str;
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
        let payload = match &data {
            Data::Out(bytes) => bytes.to_vec(),
            _ => Vec::new(),
        };
        self.calls.push((cdb.to_vec(), payload));
        match data {
            Data::Out(bytes) => {
                let index = self.writes;
                self.writes += 1;
                if self.fail_write == Some(index) {
                    return Err("write failed");
                }
                Ok(bytes.len())
            }
            Data::In(buf) => {
                if cdb[0] == 0x12 {
                    if self.short {
                        return Ok(0);
                    }
                    buf[REVISION_OFFSET..REVISION_OFFSET + REVISION_LEN]
                        .copy_from_slice(&self.revision);
                }
                if cdb == crate::cdb::test_unit_ready() && self.busy > 0 {
                    self.busy -= 1;
                    return Err("not ready");
                }
                if cdb == crate::cdb::get_event_status() && self.fail_event {
                    return Err("event unavailable");
                }
                Ok(buf.len())
            }
            Data::None => Ok(0),
        }
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}
fn options(recover: bool) -> UpdateOptions {
    UpdateOptions {
        class: DriveClass::Bd,
        recover,
    }
}

#[test]
fn transfer_order_bytes_offsets_delays_and_progress_are_preserved() {
    let kernel = vec![0xa5; 0x8001];
    let normal = vec![0x5a; 0x8001];
    let mut mock = Mock::default();
    let mut clock = Clock::default();
    execute_update(
        &mut mock,
        &mut clock,
        &[7; 256],
        UpdateTransfer {
            kernel: Some(&kernel),
            normal: &normal,
        },
        options(false),
    )
    .unwrap();
    let expected = [
        cdb::enter_update().to_vec(),
        cdb::inquiry(0x60).to_vec(),
        cdb::transfer(Role::Kernel, 0, 0x8000).to_vec(),
        cdb::transfer(Role::Kernel, 0x8000, 1).to_vec(),
        cdb::transfer(Role::Normal, 0, 0x8000).to_vec(),
        cdb::transfer(Role::Normal, 0x8000, 1).to_vec(),
        cdb::finish().to_vec(),
        cdb::get_event_status().to_vec(),
        cdb::test_unit_ready().to_vec(),
    ];
    assert_eq!(
        mock.calls.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        [mock.calls[2].1.as_slice(), mock.calls[3].1.as_slice()].concat(),
        kernel
    );
    assert_eq!(
        [mock.calls[4].1.as_slice(), mock.calls[5].1.as_slice()].concat(),
        normal
    );
    assert_eq!(mock.calls[0].1, mock.calls[6].1);
    assert_eq!(
        clock.sleeps,
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(2)
        ]
    );
    assert_eq!(
        clock.progress,
        [
            (Role::Kernel, 0x8000, 0x8001),
            (Role::Kernel, 0x8001, 0x8001),
            (Role::Normal, 0x8000, 0x8001),
            (Role::Normal, 0x8001, 0x8001)
        ]
    );
}

#[test]
fn bad_or_short_entry_revision_stops_before_components_and_recovery_skips_only_gate() {
    for short in [false, true] {
        let mut mock = Mock {
            revision: *b"1.14",
            short,
            ..Mock::default()
        };
        let result = execute_update(
            &mut mock,
            &mut Clock::default(),
            &[0; 256],
            UpdateTransfer {
                kernel: None,
                normal: &[1],
            },
            options(false),
        );
        assert!(matches!(
            result,
            Err(UpdateError::EntryState { .. })
                | Err(UpdateError::EntryStateRead(Error::Short { .. }))
        ));
        assert_eq!(mock.writes, 1);
    }
    let mut mock = Mock {
        short: true,
        ..Mock::default()
    };
    execute_update(
        &mut mock,
        &mut Clock::default(),
        &[0; 256],
        UpdateTransfer {
            kernel: None,
            normal: &[1],
        },
        options(true),
    )
    .unwrap();
    assert!(!mock.calls.iter().any(|c| c.0[0] == 0x12));
    assert_eq!(mock.writes, 3);
}

#[test]
fn every_failed_write_aborts_without_retry_or_later_commands() {
    for fail in 0..4 {
        let mut mock = Mock {
            fail_write: Some(fail),
            ..Mock::default()
        };
        let error = execute_update(
            &mut mock,
            &mut Clock::default(),
            &[0; 256],
            UpdateTransfer {
                kernel: Some(&[2]),
                normal: &[1],
            },
            options(false),
        )
        .unwrap_err();
        match (fail, error) {
            (0, UpdateError::Entry(_)) | (3, UpdateError::Finish(_)) => {}
            (
                1,
                UpdateError::Transfer {
                    role: Role::Kernel,
                    offset: 0,
                    length: 1,
                    ..
                },
            )
            | (
                2,
                UpdateError::Transfer {
                    role: Role::Normal,
                    offset: 0,
                    length: 1,
                    ..
                },
            ) => {}
            other => panic!("unexpected failure: {other:?}"),
        }
        assert_eq!(mock.writes, fail + 1);
        assert!(!mock.calls.iter().any(|c| c.0 == cdb::test_unit_ready()));
    }
}

#[test]
fn readiness_retries_reads_only_and_preserves_the_final_timeout_error() {
    for busy in [2, usize::MAX] {
        let mut mock = Mock {
            busy,
            fail_event: true,
            ..Mock::default()
        };
        let mut clock = Clock::default();
        let result = execute_update(
            &mut mock,
            &mut clock,
            &[0; 256],
            UpdateTransfer {
                kernel: None,
                normal: &[1],
            },
            options(false),
        );
        if busy == 2 {
            result.unwrap();
            assert_eq!(clock.failures, 2);
        } else {
            assert!(matches!(
                result,
                Err(UpdateError::ReadyTimeout(Error::Transport("not ready")))
            ));
            assert_eq!(clock.now, Duration::from_secs(93));
        }
        assert_eq!(mock.writes, 3);
    }
}

#[test]
fn invalid_component_spans_are_refused_before_entry() {
    let oversized = vec![0; ADDRESS_SPACE + 1];
    for transfer in [
        UpdateTransfer {
            kernel: None,
            normal: &[],
        },
        UpdateTransfer {
            kernel: Some(&[]),
            normal: &[1],
        },
        UpdateTransfer {
            kernel: None,
            normal: &oversized,
        },
    ] {
        let mut mock = Mock::default();
        assert!(matches!(
            execute_update(
                &mut mock,
                &mut Clock::default(),
                &[0; 256],
                transfer,
                options(false)
            ),
            Err(UpdateError::InvalidSpan { .. })
        ));
        assert!(mock.calls.is_empty());
    }
}
