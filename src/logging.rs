//! Discover temporary logging support from executable firmware, without model tables.

const SET_PERSISTENT: u8 = 0x10;
const GET_MASK: u8 = 0x11;
const SET_RAM: u8 = 0x12;
#[cfg(feature = "drive")]
const SUPPLIED_MASK: u8 = 1;
const MASK_LEN: usize = core::mem::size_of::<u32>();
#[cfg(feature = "drive")]
const PAYLOAD_MASK_OFFSET: usize = 3;
const CDB_ARRIVAL_BIT: u32 = 0x0004_0000;
const LOW_RAM_END: u32 = 0x8000;
const ADDRESS_MASK: u32 = 0x00ff_ffff;
const DISPATCH_ENTRY_LEN: usize = 12;
const DISPATCH_CALLBACK_OFFSET: usize = 8;
// H8SX instruction sequences. Addresses and branch destinations are decoded,
// while register/branch structure must match the audited implementation.
const HANDLER_PROLOGUE: &[u8] = &[1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 8];
const MASK_LOAD: &[u8] = &[1, 0, 0x6b, 0x20];
const PERSISTENT_BRANCH: &[u8] = &[0xf9, 1, 0x0f, 0xa0, 0x5e];
const TEMPORARY_BRANCH: &[u8] = &[0x0c, 0x11, 0x47, 4, 0x18, 0x99, 0x40, 0x1e];
const SETTER_PROLOGUE: &[u8] = &[1, 0, 0x6d, 0xf3, 0x0f, 0x83, 1, 0, 0x6b, 0xa0];
const SKIP_PERSISTENCE: &[u8] = &[0x0c, 0x99, 0x47, 0x1e];
const SETTER_RETURN: &[u8] = &[1, 0, 0x6d, 0x73, 0x54, 0x70];
const SETTER_RETURN_OFFSET: usize = 48;
const TEMPORARY_JUMP_TARGET: usize = 0x26;
const COMPARE_BRANCH_LEN: usize = 6;
const ARRIVAL_TEST: &[u8] = &[0x19, 0x99, 0x0f, 0x80, 0x47, 4];

/// A structurally verified temporary logging handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoggingLayout {
    /// Live RAM variable read by the CDB arrival logger.
    mask_address: u32,
    /// Internal dispatcher group containing the temporary setter.
    group: u8,
    /// Bit tested by the CDB arrival logger.
    bit: u32,
}

impl LoggingLayout {
    /// Address of the verified live mask variable.
    pub fn mask_address(self) -> u32 {
        self.mask_address
    }
    /// Internal dispatcher group containing the verified setter.
    pub fn group(self) -> u8 {
        self.group
    }
    /// CDB arrival logging bit in the mask.
    pub fn bit(self) -> u32 {
        self.bit
    }
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn branch(b: &[u8], at: usize) -> Option<usize> {
    let delta = i16::from_be_bytes(b.get(at + 4..at + 6)?.try_into().ok()?);
    (at + 6).checked_add_signed(delta as isize)
}
fn is(b: &[u8], at: usize, value: &[u8]) -> bool {
    b.get(at..at.saturating_add(value.len())) == Some(value)
}

/// Inspect an address-aligned CPU image. Unsupported or ambiguous code returns `None`.
/// Requires the 10/11/12 dispatcher, RAM-only branch, matching getter/setter,
/// direct dispatch-table binding and the CDB arrival mask test. No hash/model list.
pub fn discover(image: &[u8]) -> Option<LoggingLayout> {
    let mut found = None;
    for p in HANDLER_PROLOGUE.len()..image.len().saturating_sub(3 * COMPARE_BRANCH_LEN) {
        if !is(image, p, &[0xa9, SET_PERSISTENT, 0x58, 0x70])
            || !is(image, p + COMPARE_BRANCH_LEN, &[0xa9, GET_MASK, 0x58, 0x70])
            || !is(
                image,
                p + 2 * COMPARE_BRANCH_LEN,
                &[0xa9, SET_RAM, 0x58, 0x70],
            )
            || !is(image, p - HANDLER_PROLOGUE.len(), HANDLER_PROLOGUE)
        {
            continue;
        }
        let Some(candidate) = candidate(image, p) else {
            continue;
        };
        if found.is_some() {
            return None;
        }
        found = Some(candidate);
    }
    found
}

fn candidate(b: &[u8], p: usize) -> Option<LoggingLayout> {
    let persistent = branch(b, p)?;
    let getter = branch(b, p + COMPARE_BRANCH_LEN)?;
    let temporary = branch(b, p + 2 * COMPARE_BRANCH_LEN)?;
    if !is(b, persistent, PERSISTENT_BRANCH)
        || !is(b, getter, MASK_LOAD)
        || !is(b, temporary, TEMPORARY_BRANCH)
        || temporary.checked_add(TEMPORARY_JUMP_TARGET)? != persistent + 2
    {
        return None;
    }
    let address = be32(b, getter + MASK_LOAD.len())?;
    if address >= LOW_RAM_END {
        return None;
    }
    let setter = (be32(b, persistent + 4)? & ADDRESS_MASK) as usize;
    if !is(b, setter, SETTER_PROLOGUE)
        || be32(b, setter + SETTER_PROLOGUE.len())? != address
        || !is(
            b,
            setter + SETTER_PROLOGUE.len() + MASK_LEN,
            SKIP_PERSISTENCE,
        )
        || !is(b, setter + SETTER_RETURN_OFFSET, SETTER_RETURN)
    {
        return None;
    }
    // The supplied-value branch clears r1l and jumps directly to the setter;
    // its zero flag bypasses every persistent-settings call in that setter.
    let mut table = None;
    for entry in b.windows(DISPATCH_ENTRY_LEN) {
        if entry[0] >= 0x80
            && entry[1..DISPATCH_CALLBACK_OFFSET] == [0, 0, 0, 0, 0, 0xff, 0xff]
            && u32::from_be_bytes(
                entry[DISPATCH_CALLBACK_OFFSET..DISPATCH_ENTRY_LEN]
                    .try_into()
                    .ok()?,
            ) == (p - HANDLER_PROLOGUE.len()) as u32
        {
            if table.is_some() {
                return None;
            }
            table = Some(entry[0]);
        }
    }
    // Arrival path: read this mask, AND 0x40000, then conditional log emission.
    let mut gate = [0u8; 20];
    gate[..4].copy_from_slice(MASK_LOAD);
    gate[4..8].copy_from_slice(&address.to_be_bytes());
    gate[8..10].copy_from_slice(&[0x7a, 0x60]); // and.l #immediate,er0
    gate[10..14].copy_from_slice(&CDB_ARRIVAL_BIT.to_be_bytes());
    gate[14..].copy_from_slice(ARRIVAL_TEST);
    if !b.windows(gate.len()).any(|w| w == gate) {
        return None;
    }
    Some(LoggingLayout {
        mask_address: address,
        group: table?,
        bit: CDB_ARRIVAL_BIT,
    })
}

/// Change CDB arrival logging in RAM only. Unsupported firmware must be
/// rejected by [`discover`] first. Returns success only after the live mask is verified.
/// Use a layout discovered from the currently connected drive's firmware.
#[cfg(feature = "drive")]
pub fn set_logging_ram<T: crate::drive::Transport>(
    t: &mut T,
    layout: LoggingLayout,
    enabled: bool,
) -> Result<(), crate::drive::Error<T::Error>> {
    set_logging(t, layout, enabled, false)
}

/// Change the persistent CDB arrival logging setting. This explicitly writes
/// nonvolatile settings; never use it as a fallback for a temporary request.
/// Readback verifies the live mask, not persistence across a power cycle.
#[cfg(feature = "drive")]
pub fn set_logging_persistent<T: crate::drive::Transport>(
    t: &mut T,
    layout: LoggingLayout,
    enabled: bool,
) -> Result<(), crate::drive::Error<T::Error>> {
    set_logging(t, layout, enabled, true)
}

#[cfg(feature = "drive")]
fn set_logging<T: crate::drive::Transport>(
    t: &mut T,
    layout: LoggingLayout,
    enabled: bool,
    persistent: bool,
) -> Result<(), crate::drive::Error<T::Error>> {
    use crate::{
        cdb,
        drive::{self, Error},
    };
    let mut mask = [0u8; MASK_LEN];
    let cdb = cdb::read_memory(layout.mask_address, MASK_LEN as u32);
    drive::read(t, &cdb, &mut mask, MASK_LEN)?;
    let before = u32::from_be_bytes(mask);
    let after = if enabled {
        before | layout.bit
    } else {
        before & !layout.bit
    };
    // A matching RAM value does not prove the persistent value matches.
    if before == after && !persistent {
        return Ok(());
    }
    let mut payload = [0u8; cdb::DIAGNOSTIC_CONTROL_LEN as usize];
    payload[..PAYLOAD_MASK_OFFSET].copy_from_slice(&[
        layout.group,
        if persistent { SET_PERSISTENT } else { SET_RAM },
        SUPPLIED_MASK,
    ]);
    payload[PAYLOAD_MASK_OFFSET..PAYLOAD_MASK_OFFSET + MASK_LEN]
        .copy_from_slice(&after.to_be_bytes());
    drive::write(t, &cdb::write_diagnostic_control(), &payload)?;
    drive::read(t, &cdb, &mut mask, MASK_LEN)?;
    let actual = u32::from_be_bytes(mask);
    if actual != after {
        return Err(Error::ReadbackMismatch {
            expected: after,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod tests;
