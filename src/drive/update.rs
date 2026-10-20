//! One bounded OEM update session over an already validated transfer.

use super::{enter_update, read, Control, Data, Error, Transport};
use crate::{cdb, DriveClass, Role};
use core::time::Duration;

const CHUNK_LEN: usize = 0x8000;
const ADDRESS_SPACE: usize = 0x100_0000;
const ENTRY_SETTLE: Duration = Duration::from_secs(1);
const KERNEL_SETTLE: Duration = Duration::from_secs(2);
const FINISH_SETTLE: Duration = Duration::from_secs(2);
const POLL_TIMEOUT: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const INQUIRY_ALLOCATION: usize = 0x60;
const REVISION_OFFSET: usize = 0x20;
const REVISION_LEN: usize = 4;
const UPDATE_REVISION: &[u8] = b"000";
const EVENT_ALLOCATION: usize = 8;

/// Canonical component bytes for a single OEM update session.
///
/// This layer checks transfer bounds, not firmware validity or compatibility.
/// Supply receiver-prepared bytes and retain any required restoration plan.
#[derive(Clone, Copy, Debug)]
pub struct UpdateTransfer<'a> {
    /// Optional canonical front-key Kernel transfer.
    pub kernel: Option<&'a [u8]>,
    /// Required canonical Normal transfer.
    pub normal: &'a [u8],
}

/// One contiguous run of a component delivered to a single receive buffer.
///
/// A plan's segments are written in order. `bytes` is split into
/// `max_chunk`-sized `WRITE BUFFER` commands addressed from `dest_offset`, all
/// to buffer `buffer_id`. `role` labels the segment for progress and settle
/// timing only; it does not pick the buffer. This is how one component (e.g. a
/// Kernel whose loader stages the body and its header to different receive
/// buffers) spreads across more than one destination.
#[derive(Clone, Copy, Debug)]
pub struct Segment<'a> {
    /// Component this segment belongs to, for progress and post-settle.
    pub role: Role,
    /// Receive buffer the chunks are written to (e.g. [`cdb::KERNEL_ID`]).
    pub buffer_id: u8,
    /// Wire offset of the first chunk within `buffer_id`.
    pub dest_offset: u32,
    /// Payload for this segment.
    pub bytes: &'a [u8],
    /// Largest `WRITE BUFFER` data-out this segment uses.
    pub max_chunk: u32,
}

impl Segment<'_> {
    /// A filler segment for initialising fixed-size plan storage before the
    /// real segments are written in; never transferred.
    pub const PLACEHOLDER: Segment<'static> = Segment {
        role: Role::Normal,
        buffer_id: cdb::NORMAL_ID,
        dest_offset: 0,
        bytes: &[],
        max_chunk: 1,
    };
}

/// An ordered receive plan: the exact buffers, offsets and chunking a specific
/// installed loader accepts for an update. The linear one-buffer-per-role form
/// is just the common case ([`UpdateTransfer`] builds it); a loader with a
/// multi-destination receiver supplies its own segments instead.
#[derive(Clone, Copy, Debug)]
pub struct Plan<'a> {
    /// Segments written in order.
    pub segments: &'a [Segment<'a>],
}

/// Entry dialect and explicitly requested recovery behavior.
#[derive(Clone, Copy, Debug)]
pub struct UpdateOptions {
    /// Dialect established by the caller from the live receiver.
    pub class: DriveClass,
    /// Skip the post-entry revision gate for a degraded receiver.
    pub recover: bool,
}

/// Host timing and progress services, independent of a UI or operating system.
pub trait UpdateRuntime {
    /// A validated single-pass transfer is about to enter update mode.
    fn starting(&mut self, _kernel_bytes: usize, _normal_bytes: usize) {}
    /// Monotonic elapsed time from a fixed origin; must advance during sleeps.
    fn elapsed(&self) -> Duration;
    /// Wait at least the requested duration.
    fn sleep(&mut self, duration: Duration);
    /// A component chunk completed successfully.
    fn progress(&mut self, _role: Role, _written: usize, _total: usize) {}
    /// Entry completed and the revision gate passed or was explicitly skipped.
    fn entered(&mut self, _recover: bool) {}
    /// A readiness probe failed; no firmware transfer is retried.
    fn poll_failed(&mut self, _elapsed: Duration, _error: &dyn core::fmt::Debug) {}
}

/// Failure stage in one update session. Transfer and finish failures may leave
/// partially programmed firmware; no automatic retry or rollback is performed.
#[derive(Debug)]
#[non_exhaustive]
pub enum UpdateError<E> {
    /// A component is empty or exceeds the CDB address space; no entry attempted.
    InvalidSpan {
        /// Invalid component.
        role: Role,
        /// Component byte count.
        length: usize,
    },
    /// Entry or its DVR handshake failed.
    Entry(Error<E>),
    /// Reading the post-entry revision failed.
    EntryStateRead(Error<E>),
    /// The post-entry revision did not report update mode.
    EntryState {
        /// Four revision bytes returned by INQUIRY.
        revision: [u8; REVISION_LEN],
    },
    /// A component write failed and was not retried.
    Transfer {
        /// Component being transferred.
        role: Role,
        /// Component-relative byte offset.
        offset: u32,
        /// Bytes requested in this write.
        length: usize,
        /// Underlying command failure.
        source: Error<E>,
    },
    /// The finish command failed.
    Finish(Error<E>),
    /// Readiness polling expired, preserving the last failed probe.
    ReadyTimeout(Error<E>),
}

impl<E: core::fmt::Debug> core::fmt::Display for UpdateError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSpan { role, length } => write!(
                f,
                "{role:?} transfer length {length:#x} is empty or exceeds the CDB address space"
            ),
            Self::Entry(error) => write!(f, "update entry: {error}"),
            Self::EntryStateRead(error) => write!(f, "post-entry INQUIRY: {error}"),
            Self::EntryState { revision } => write!(
                f,
                "post-entry revision {revision:02x?} does not report update mode"
            ),
            Self::Transfer {
                role,
                offset,
                length,
                source,
            } => write!(
                f,
                "{role:?} write at {offset:#x}, length {length}: {source}"
            ),
            Self::Finish(error) => write!(f, "update finish: {error}"),
            Self::ReadyTimeout(error) => write!(f, "post-update readiness timed out: {error}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + 'static> std::error::Error for UpdateError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Entry(e) | Self::EntryStateRead(e) | Self::Finish(e) | Self::ReadyTimeout(e) => {
                Some(e)
            }
            Self::Transfer { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Execute entry, revision gate, ordered component writes, finish and readiness.
///
/// The caller must establish compatibility, capture a backup, bind the control
/// buffer to the live receiver and enforce its tray/consent policy first. Use
/// a strict transport that never retries writes. This executes one pass only;
/// it does not perform readback or a prepared pristine-restoration pass.
pub fn execute_update<T: Transport, R: UpdateRuntime>(
    transport: &mut T,
    runtime: &mut R,
    control: &Control,
    transfer: UpdateTransfer<'_>,
    options: UpdateOptions,
) -> Result<(), UpdateError<T::Error>> {
    let mut storage = [Segment::PLACEHOLDER; 2];
    let mut len = 0;
    if let Some(kernel) = transfer.kernel {
        storage[len] = Segment {
            role: Role::Kernel,
            buffer_id: cdb::KERNEL_ID,
            dest_offset: 0,
            bytes: kernel,
            max_chunk: CHUNK_LEN as u32,
        };
        len += 1;
    }
    storage[len] = Segment {
        role: Role::Normal,
        buffer_id: cdb::NORMAL_ID,
        dest_offset: 0,
        bytes: transfer.normal,
        max_chunk: CHUNK_LEN as u32,
    };
    len += 1;
    execute_plan(
        transport,
        runtime,
        control,
        Plan {
            segments: &storage[..len],
        },
        options,
    )
}

/// Total bytes in `plan` tagged with `role`.
fn role_total(plan: Plan<'_>, role: Role) -> usize {
    plan.segments
        .iter()
        .filter(|s| s.role == role)
        .map(|s| s.bytes.len())
        .sum()
}

/// Execute entry, revision gate, an ordered receive [`Plan`], finish and
/// readiness. [`execute_update`] is the linear-plan special case of this.
///
/// The caller must establish compatibility, capture a backup, bind the control
/// buffer to the live receiver and enforce its tray/consent policy first. Use a
/// strict transport that never retries writes. One pass only; no readback or
/// pristine-restoration pass.
pub fn execute_plan<T: Transport, R: UpdateRuntime>(
    transport: &mut T,
    runtime: &mut R,
    control: &Control,
    plan: Plan<'_>,
    options: UpdateOptions,
) -> Result<(), UpdateError<T::Error>> {
    for segment in plan.segments {
        let end = segment.dest_offset as usize + segment.bytes.len();
        if segment.bytes.is_empty() || segment.max_chunk == 0 || end > ADDRESS_SPACE {
            return Err(UpdateError::InvalidSpan {
                role: segment.role,
                length: segment.bytes.len(),
            });
        }
    }
    let kernel_bytes = role_total(plan, Role::Kernel);
    let normal_bytes = role_total(plan, Role::Normal);
    runtime.starting(kernel_bytes, normal_bytes);
    let mut session =
        enter_update(transport, options.class, control).map_err(UpdateError::Entry)?;
    runtime.sleep(ENTRY_SETTLE);
    if !options.recover {
        let mut inquiry = [0; INQUIRY_ALLOCATION];
        read(
            session.t,
            &cdb::inquiry(INQUIRY_ALLOCATION as u8),
            &mut inquiry,
            REVISION_OFFSET + REVISION_LEN,
        )
        .map_err(UpdateError::EntryStateRead)?;
        let mut revision = [0; REVISION_LEN];
        revision.copy_from_slice(&inquiry[REVISION_OFFSET..REVISION_OFFSET + REVISION_LEN]);
        if !revision.starts_with(UPDATE_REVISION) {
            return Err(UpdateError::EntryState { revision });
        }
    }
    runtime.entered(options.recover);
    let last_kernel = plan.segments.iter().rposition(|s| s.role == Role::Kernel);
    for (index, segment) in plan.segments.iter().enumerate() {
        // Cumulative progress across every earlier segment of the same role, so
        // a multi-segment component still reports one monotonic total.
        let mut done: usize = plan.segments[..index]
            .iter()
            .filter(|s| s.role == segment.role)
            .map(|s| s.bytes.len())
            .sum();
        let component_total = if segment.role == Role::Kernel {
            kernel_bytes
        } else {
            normal_bytes
        };
        let mut written = 0usize;
        for chunk in segment.bytes.chunks(segment.max_chunk as usize) {
            let offset = segment.dest_offset + written as u32;
            session
                .write_raw(segment.buffer_id, offset, chunk)
                .map_err(|source| UpdateError::Transfer {
                    role: segment.role,
                    offset,
                    length: chunk.len(),
                    source,
                })?;
            written += chunk.len();
            done += chunk.len();
            runtime.progress(segment.role, done, component_total);
        }
        if Some(index) == last_kernel {
            runtime.sleep(KERNEL_SETTLE);
        }
    }
    session.finish().map_err(UpdateError::Finish)?;
    runtime.sleep(FINISH_SETTLE);
    let start = runtime.elapsed();
    loop {
        // The resident loader rejects other opcodes while its programming
        // counter is nonzero, bypassing the end-of-command restart check.
        // REQUEST SENSE is allowed through that guard, even after programming
        // finishes but before the restart resets the counter. It is not proof
        // of readiness: still require TEST UNIT READY below.
        let mut sense = [0; 18];
        let _ = transport.exec(&cdb::request_sense(18), Data::In(&mut sense));
        let mut event = [0; EVENT_ALLOCATION];
        let _ = transport.exec(&cdb::get_event_status(), Data::In(&mut event));
        // TEST UNIT READY has a zero-length data-in phase in existing adapters.
        match super::exec(transport, &cdb::test_unit_ready(), Data::In(&mut [])) {
            Ok(_) => return Ok(()),
            Err(error) => {
                let elapsed = runtime.elapsed().saturating_sub(start);
                runtime.poll_failed(elapsed, &error);
                if elapsed >= POLL_TIMEOUT {
                    return Err(UpdateError::ReadyTimeout(error));
                }
                runtime.sleep(POLL_INTERVAL);
            }
        }
    }
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
