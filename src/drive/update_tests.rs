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
    restart_pending: bool,
    require_sense_restart: bool,
    fail_sense: bool,
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
            restart_pending: false,
            require_sense_restart: false,
            fail_sense: false,
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
                if cdb == crate::cdb::finish() && self.require_sense_restart {
                    self.restart_pending = true;
                }
                Ok(bytes.len())
            }
            Data::In(buf) => {
                if cdb == crate::cdb::request_sense(18) && self.fail_sense {
                    return Err("sense unavailable");
                }
                if self.restart_pending {
                    if cdb == crate::cdb::request_sense(18) {
                        self.restart_pending = false;
                    } else {
                        return Err("programming counter still set: initializing command required");
                    }
                }
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
fn programming_counter_requires_request_sense_to_reach_restart() {
    // WX1DM 1.01 Kernel: 402b00 checks 14d; only opcode 03 bypasses
    // the busy return at 402b26 and reaches the restart check at 402b72.
    let mut mock = Mock {
        require_sense_restart: true,
        ..Mock::default()
    };
    let mut clock = Clock::default();
    execute_update(
        &mut mock,
        &mut clock,
        &[7; 256],
        UpdateTransfer {
            kernel: None,
            normal: &[1; 256],
        },
        options(true),
    )
    .unwrap();
    assert!(!mock.restart_pending);
    assert_eq!(clock.failures, 0);
    let finish = mock
        .calls
        .iter()
        .position(|c| c.0 == cdb::finish())
        .unwrap();
    assert_eq!(mock.calls[finish + 1].0, cdb::request_sense(18));
    assert_eq!(mock.calls.last().unwrap().0, cdb::test_unit_ready());
}

#[test]
fn sense_failure_neither_reports_ready_nor_retries_the_update() {
    for require_sense_restart in [false, true] {
        let mut mock = Mock {
            fail_sense: true,
            require_sense_restart,
            ..Mock::default()
        };
        let mut clock = Clock::default();
        let result = execute_update(
            &mut mock,
            &mut clock,
            &[7; 256],
            UpdateTransfer {
                kernel: None,
                normal: &[1; 256],
            },
            options(true),
        );
        if require_sense_restart {
            assert!(matches!(result, Err(UpdateError::ReadyTimeout(_))));
            assert!(mock.restart_pending);
        } else {
            // A receiver that is ready does not need a successful sense read.
            result.unwrap();
        }
        assert_eq!(
            mock.calls.iter().filter(|c| c.0 == cdb::finish()).count(),
            1
        );
        assert_eq!(mock.writes, 3); // entry, Normal, finish; no write retries
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
        cdb::request_sense(18).to_vec(),
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
fn two_region_kernel_plan_preserves_front_then_body_placement() {
    // Header/key at zero, then body at 0x1200; Normal follows the Kernel.
    let body = vec![0xa5u8; 0x1_0000];
    let front = vec![0x5au8; 0x1200];
    let normal = vec![0x33u8; 0x8000];
    let segments = [
        Segment {
            role: Role::Kernel,
            buffer_id: cdb::KERNEL_ID,
            dest_offset: 0,
            bytes: &front,
            max_chunk: 0x8000,
        },
        Segment {
            role: Role::Kernel,
            buffer_id: cdb::KERNEL_ID,
            dest_offset: 0x1200,
            bytes: &body,
            max_chunk: 0x8000,
        },
        Segment {
            role: Role::Normal,
            buffer_id: cdb::NORMAL_ID,
            dest_offset: 0,
            bytes: &normal,
            max_chunk: 0x8000,
        },
    ];
    let mut mock = Mock::default();
    let mut clock = Clock::default();
    execute_plan(
        &mut mock,
        &mut clock,
        &[7; 256],
        Plan {
            segments: &segments,
        },
        options(false),
    )
    .unwrap();

    let expected = [
        cdb::enter_update().to_vec(),
        cdb::inquiry(0x60).to_vec(),
        cdb::transfer_with_id(cdb::KERNEL_ID, 0, 0x1200).to_vec(),
        cdb::transfer_with_id(cdb::KERNEL_ID, 0x1200, 0x8000).to_vec(),
        cdb::transfer_with_id(cdb::KERNEL_ID, 0x9200, 0x8000).to_vec(),
        cdb::transfer_with_id(cdb::NORMAL_ID, 0, 0x8000).to_vec(),
        cdb::finish().to_vec(),
        cdb::request_sense(18).to_vec(),
        cdb::get_event_status().to_vec(),
        cdb::test_unit_ready().to_vec(),
    ];
    assert_eq!(
        mock.calls.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
        expected
    );
    assert_eq!(mock.calls[2].0, [0x3b, 0x07, 0xfe, 0, 0, 0, 0, 0x12, 0, 0]);
    assert_eq!(mock.calls[2].1, front);
    assert_eq!(
        [mock.calls[3].1.as_slice(), mock.calls[4].1.as_slice()].concat(),
        body
    );
    assert_eq!(mock.calls[5].1, normal);
    // One Kernel settle after both segments.
    assert_eq!(
        clock.sleeps,
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(2)
        ]
    );
    // Kernel progress is cumulative across both kernel segments (0x11200 total).
    assert_eq!(
        clock.progress,
        [
            (Role::Kernel, 0x1200, 0x1_1200),
            (Role::Kernel, 0x9200, 0x1_1200),
            (Role::Kernel, 0x1_1200, 0x1_1200),
            (Role::Normal, 0x8000, 0x8000),
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

#[test]
fn all_segment_bounds_are_checked_before_entry_or_loader_resume() {
    let too_large_chunk = vec![0; ADDRESS_SPACE];
    for segment in [
        Segment {
            bytes: &[1],
            dest_offset: 0x100_0000,
            ..Segment::PLACEHOLDER
        },
        Segment {
            bytes: &[1],
            max_chunk: 0,
            ..Segment::PLACEHOLDER
        },
        Segment {
            bytes: &too_large_chunk,
            max_chunk: ADDRESS_SPACE as u32,
            ..Segment::PLACEHOLDER
        },
    ] {
        for already_updating in [false, true] {
            let mut mock = Mock::default();
            assert!(matches!(
                execute_plan_with_entry(
                    &mut mock,
                    &mut Clock::default(),
                    &[0; 256],
                    Plan {
                        segments: &[segment]
                    },
                    options(true),
                    already_updating
                ),
                Err(UpdateError::InvalidSpan { .. })
            ));
            assert!(mock.calls.is_empty());
        }
    }
    assert!(validate_plan::<()>(Plan { segments: &[] }).is_err());
}
