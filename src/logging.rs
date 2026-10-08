//! Discover temporary logging support from executable firmware, without model tables.

use alloc::vec;

/// A structurally verified temporary logging handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Logging {
    /// Live RAM variable read by the CDB arrival logger.
    mask_address: u32,
    /// Internal dispatcher group containing the temporary setter.
    group: u8,
    /// Bit tested by the CDB arrival logger.
    bit: u32,
}

impl Logging {
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
pub fn discover(image: &[u8]) -> Option<Logging> {
    let mut found = None;
    for p in 8..image.len().saturating_sub(18) {
        if !is(image, p, &[0xa9, 0x10, 0x58, 0x70])
            || !is(image, p + 6, &[0xa9, 0x11, 0x58, 0x70])
            || !is(image, p + 12, &[0xa9, 0x12, 0x58, 0x70])
            || !is(image, p - 8, &[1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 8])
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

fn candidate(b: &[u8], p: usize) -> Option<Logging> {
    let persistent = branch(b, p)?;
    let getter = branch(b, p + 6)?;
    let temporary = branch(b, p + 12)?;
    if !is(b, persistent, &[0xf9, 1, 0x0f, 0xa0, 0x5e])
        || !is(b, getter, &[1, 0, 0x6b, 0x20])
        || !is(b, temporary, &[0x0c, 0x11, 0x47, 4, 0x18, 0x99, 0x40, 0x1e])
        || temporary.checked_add(0x26)? != persistent + 2
    {
        return None;
    }
    let address = be32(b, getter + 4)?;
    if address >= 0x8000 {
        return None;
    }
    let setter = (be32(b, persistent + 4)? & 0x00ff_ffff) as usize;
    if !is(b, setter, &[1, 0, 0x6d, 0xf3, 0x0f, 0x83, 1, 0, 0x6b, 0xa0])
        || be32(b, setter + 10)? != address
        || !is(b, setter + 14, &[0x0c, 0x99, 0x47, 0x1e])
        || !is(b, setter + 48, &[1, 0, 0x6d, 0x73, 0x54, 0x70])
    {
        return None;
    }
    // The supplied-value branch clears r1l and jumps directly to the setter;
    // its zero flag bypasses every persistent-settings call in that setter.
    let mut table = None;
    for entry in b.windows(12) {
        if entry[0] >= 0x80
            && entry[1..8] == [0, 0, 0, 0, 0, 0xff, 0xff]
            && u32::from_be_bytes(entry[8..12].try_into().ok()?) == (p - 8) as u32
        {
            if table.is_some() {
                return None;
            }
            table = Some(entry[0]);
        }
    }
    // Arrival path: read this mask, AND 0x40000, then conditional log emission.
    let mut gate = vec![1, 0, 0x6b, 0x20];
    gate.extend_from_slice(&address.to_be_bytes());
    gate.extend_from_slice(&[0x7a, 0x60, 0, 4, 0, 0, 0x19, 0x99, 0x0f, 0x80, 0x47, 4]);
    if !b.windows(gate.len()).any(|w| w == gate) {
        return None;
    }
    Some(Logging {
        mask_address: address,
        group: table?,
        bit: 0x40000,
    })
}

/// Change CDB arrival logging in RAM only. Unsupported firmware must be
/// rejected by [`discover`] first. Returns whether the live mask was verified.
#[cfg(feature = "drive")]
pub fn set_logging_ram<T: crate::drive::Transport>(
    t: &mut T,
    layout: Logging,
    enabled: bool,
) -> Result<bool, crate::drive::Error<T::Error>> {
    set_logging(t, layout, enabled, false)
}

/// Change the persistent CDB arrival logging setting. This explicitly writes
/// nonvolatile settings; never use it as a fallback for a temporary request.
/// Readback verifies the live mask, not persistence across a power cycle.
#[cfg(feature = "drive")]
pub fn set_logging_persistent<T: crate::drive::Transport>(
    t: &mut T,
    layout: Logging,
    enabled: bool,
) -> Result<bool, crate::drive::Error<T::Error>> {
    set_logging(t, layout, enabled, true)
}

#[cfg(feature = "drive")]
fn set_logging<T: crate::drive::Transport>(
    t: &mut T,
    layout: Logging,
    enabled: bool,
    persistent: bool,
) -> Result<bool, crate::drive::Error<T::Error>> {
    use crate::{
        cdb,
        drive::{Data, Error},
    };
    let mut mask = [0u8; 4];
    let cdb = cdb::read_memory(layout.mask_address, 4);
    let n = t
        .exec(&cdb, Data::In(&mut mask))
        .map_err(Error::Transport)?;
    if n != 4 {
        return Err(Error::Short {
            expected: 4,
            actual: n,
        });
    }
    let before = u32::from_be_bytes(mask);
    let after = if enabled {
        before | layout.bit
    } else {
        before & !layout.bit
    };
    // A matching RAM value does not prove the persistent value matches.
    if before == after && !persistent {
        return Ok(true);
    }
    let mut payload = [0u8; 32];
    payload[..3].copy_from_slice(&[layout.group, if persistent { 0x10 } else { 0x12 }, 1]);
    payload[3..7].copy_from_slice(&after.to_be_bytes());
    let n = t
        .exec(&cdb::diagnostic_control(), Data::Out(&payload))
        .map_err(Error::Transport)?;
    if n != 32 {
        return Err(Error::Short {
            expected: 32,
            actual: n,
        });
    }
    let n = t
        .exec(&cdb, Data::In(&mut mask))
        .map_err(Error::Transport)?;
    if n != 4 {
        return Err(Error::Short {
            expected: 4,
            actual: n,
        });
    }
    Ok(u32::from_be_bytes(mask) == after)
}

#[cfg(test)]
#[path = "logging_tests.rs"]
mod tests;
