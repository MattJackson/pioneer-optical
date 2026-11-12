//! Native interpretation of the unit's existing 0x112/0x113 calibration words.
//! Only reader/consumer code changes; no persistent calibration value is copied or written.
use super::*;
use core::ops::Range;

/// Native four-mode caller and low-byte return contract.
pub mod callers;

/// Interpretation established by the complete native reader program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Convention {
    /// One calibration value per stored word; calibration callers consume its low byte.
    WholeWord,
    /// Mode selects one byte of a persistent word.
    PackedBytes,
}
/// Why the native reader rewrite could not be proved.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// No unique complete reader and getter relationship was found.
    Unresolved,
    /// A larger reader needs caller-reserved executable space.
    SpaceRequired,
    /// The reservation is not an erased, aligned, stored, nonoverlapping span.
    InvalidSpace,
    /// Output recognition disagreed with the requested convention.
    VerificationFailed,
}

const WHOLE: &[u8] = &[
    0x0c, 0x88, 0x47, 0x16, 0xa8, 1, 0x47, 0x12, 0xa8, 2, 0x47, 8, 0xa8, 3, 0x47, 4, 0xf8, 0xff,
    0x40, 0x0e, 0x79, 0, 1, 0x13, 0x40, 4, 0x79, 0, 1, 0x12, 0x5e, 0, 0, 0, 0x54, 0x70,
];
const PACKED: &[u8] = &[
    0x6d, 0xf3, 0x0c, 0x89, 0x79, 3, 0, 0xff, 0x0d, 0x30, 0x0c, 0x99, 0x47, 0x22, 0xa9, 1, 0x47,
    0x14, 0xa9, 2, 0x47, 0x0a, 0xa9, 3, 0x46, 0x24, 0x79, 0, 1, 0x13, 0x40, 0x0a, 0x79, 0, 1, 0x13,
    0x40, 0x0e, 0x79, 0, 1, 0x12, 0x5e, 0, 0, 0, 0x40, 0x0c, 0x79, 0, 1, 0x12, 0x5e, 0, 0, 0, 0x0c,
    8, 0x18, 0, 0x66, 0x30, 0x6d, 0x73, 0x54, 0x70,
];
/// Getter-call operand offsets in `WHOLE` and `PACKED`.
const WHOLE_CALLS: &[usize] = &[31];
const PACKED_CALLS: &[usize] = &[43, 53];
/// The packed reader's high-to-low byte copy (`MOV.B R0H,R0L`, or NOPs).
const SELECT: Range<usize> = 56..58;
#[derive(Debug)]
struct Reader {
    at: usize,
    convention: Convention,
    packed_shape: bool,
    getter: [u8; 3],
    body: super::placement::Body,
}
fn bind(normal: &[u8]) -> Result<Reader, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut found = None;
    for (packed, template, holes) in [(false, WHOLE, WHOLE_CALLS), (true, PACKED, PACKED_CALLS)] {
        let pattern: Vec<Option<u8>> = template
            .iter()
            .enumerate()
            .map(|(i, byte)| {
                if holes.iter().any(|h| (*h..*h + 3).contains(&i))
                    || (packed && SELECT.contains(&i))
                {
                    None
                } else {
                    Some(*byte)
                }
            })
            .collect();
        for at in crate::filters::phase::bundle::sites(normal, &regions.stored, &pattern[..2]) {
            let Some(body) = super::placement::read(normal, &regions.stored, at, &pattern) else {
                continue;
            };
            let bytes = &body.bytes;
            let convention = if packed {
                match &bytes[SELECT] {
                    [0x0c, 8] => Convention::PackedBytes,
                    [0, 0] => Convention::WholeWord,
                    _ => continue,
                }
            } else {
                Convention::WholeWord
            };
            let getter: [u8; 3] = bytes[holes[0]..holes[0] + 3].try_into().expect("getter");
            let address = u32::from_be_bytes([0, getter[0], getter[1], getter[2]]);
            if address & 1 != 0
                || address < 0x400000
                || address >= 0x410000 + normal.len() as u32
                || holes.iter().any(|h| bytes[*h..*h + 3] != getter)
            {
                continue;
            }
            if found.is_some() {
                return Err(Error::Unresolved);
            }
            found = Some(Reader {
                at,
                convention,
                packed_shape: packed,
                getter,
                body,
            });
        }
    }
    found.ok_or(Error::Unresolved)
}
/// Observe the complete reader and matching getter operands. A recognized
/// four-mode consumer may select packed bytes from a whole-word reader.
pub fn observe(normal: &[u8]) -> Result<Convention, Error> {
    let reader = bind(normal)?;
    if callers::observe_bound(normal, &reader)?.is_some_and(|caller| caller.high_byte_modes) {
        Ok(Convention::PackedBytes)
    } else {
        Ok(reader.convention)
    }
}

/// Preserve the installed storage interpretation at byte-consuming calibration
/// callers by rewriting a copy of target's reader.
/// Both interpretations are the effective ones of [`observe`], including a bound
/// four-mode caller's byte selection. The original target getter, callers and
/// reader entry are retained. A native packed reader can preserve whole-word
/// calibration values by removing its high-to-low byte copy; other readers are
/// replaced through [`transplant`], so growing a whole-word reader requires an
/// explicit reservation for the branch-closed suffix reached by a JMP. A
/// difference expressed only by the installed caller's byte selection is
/// refused, because the installed reader then holds no OEM selection
/// instruction to copy; see [`transplant_effective`].
pub fn rewrite(
    target: &[u8],
    installed: &[u8],
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let required = observe(installed)?;
    if observe(target)? == required {
        return Ok(target.to_vec());
    }
    let before = bind(target)?;
    let changed = if before.packed_shape && before.body.spans.len() == 1 {
        let donor = bind(installed)?;
        let mut changed = target.to_vec();
        let slot = &mut changed[before.at + SELECT.start..before.at + SELECT.end];
        if required == Convention::WholeWord {
            super::encoding::nops(slot).ok_or(Error::Unresolved)?;
        } else if donor.packed_shape {
            // Copy the actual bound OEM high-byte selection instruction.
            slot.copy_from_slice(&donor.body.bytes[SELECT]);
        } else {
            // The installed caller, not its reader, selects the packed bytes.
            return Err(Error::Unresolved);
        }
        changed
    } else {
        transplant(target, installed, reservation)?
    };
    if observe(&changed)? != required {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

/// Copy the donor's complete native calibration reader into the target. The
/// copied instructions differ from the donor's only in getter call addresses;
/// stored words are neither copied nor written. A reader that fits replaces the
/// target's reader in place, NOP-filling the rest of its span and retiring any
/// previous spill. A longer reader keeps the original entry: a branch-closed
/// prefix ends in a JMP to the remaining suffix, placed in the reservation (or
/// the target's previous spill), and other reservation bytes are NOP-filled.
/// The caller must establish ownership of any reservation used for growth and
/// prove the getter/caller ABI, including which returned bytes are consumed.
pub fn transplant(
    target: &[u8],
    donor: &[u8],
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let before = bind(target)?;
    let source = bind(donor)?;
    let mut code = source.body.bytes.clone();
    let fields = if source.packed_shape {
        PACKED_CALLS
    } else {
        WHOLE_CALLS
    };
    for field in fields {
        super::encoding::retarget_call(
            &mut code,
            *field - 1,
            u32::from_be_bytes([0, before.getter[0], before.getter[1], before.getter[2]]),
        )
        .ok_or(Error::Unresolved)?;
    }
    if code == before.body.bytes {
        return Ok(target.to_vec());
    }
    let original = before.body.spans[0].clone();
    let prior_spill = before.body.spans.get(1);
    let mut changed = target.to_vec();
    if code.len() <= original.len() {
        crate::filters::phase::native::encoding::nops(&mut changed[original.clone()])
            .ok_or(Error::InvalidSpace)?;
        changed[original.start..original.start + code.len()].copy_from_slice(&code);
        if let Some(retired) = prior_spill {
            super::encoding::nops(&mut changed[retired.clone()]).ok_or(Error::InvalidSpace)?;
        }
    } else {
        let space = reservation
            .or_else(|| prior_spill.cloned())
            .ok_or(Error::SpaceRequired)?;
        let reusing_spill = prior_spill == Some(&space);
        let regions = crate::image::regions(target).ok_or(Error::Unresolved)?;
        let stored = regions.stored.iter().any(|region| {
            let at = region.as_ptr() as usize - target.as_ptr() as usize;
            space.start >= at && space.end <= at + region.len()
        });
        if space.start & 1 != 0
            || space.end & 1 != 0
            || space.start > space.end
            || !stored
            || (space.start < original.end && original.start < space.end)
            || (!reusing_spill
                && !target
                    .get(space.clone())
                    .is_some_and(|bytes| bytes.iter().all(|b| *b == 0xff)))
            || prior_spill
                .is_some_and(|p| !reusing_spill && space.start < p.end && p.start < space.end)
        {
            return Err(Error::InvalidSpace);
        }
        let address = 0x410000usize
            .checked_add(space.start)
            .filter(|a| *a <= 0xffffff)
            .ok_or(Error::InvalidSpace)? as u32;
        let original_address = u32::try_from(
            0x410000usize
                .checked_add(original.start)
                .ok_or(Error::InvalidSpace)?,
        )
        .map_err(|_| Error::InvalidSpace)?;
        let (prefix, spill) =
            super::placement::split_closed(&code, original_address, original.len(), address)
                .ok_or(Error::Unresolved)?;
        if spill.len() > space.len() {
            return Err(Error::InvalidSpace);
        }
        super::encoding::nops(&mut changed[space.clone()]).ok_or(Error::InvalidSpace)?;
        changed[original].copy_from_slice(&prefix);
        changed[space.start..space.start + spill.len()].copy_from_slice(&spill);
        if let Some(retired) = prior_spill.filter(|_| !reusing_spill) {
            super::encoding::nops(&mut changed[retired.clone()]).ok_or(Error::InvalidSpace)?;
        }
    }
    let actual = bind(&changed)?;
    if actual.convention != source.convention
        || actual.packed_shape != source.packed_shape
        || actual.getter != before.getter
    {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

/// Preserve the installed byte interpretation at the positively bound four-mode
/// caller. A whole-word target already returns both packed bytes, so selecting
/// its existing high-byte results avoids reader growth entirely. The result must
/// reproduce the donor's effective [`observe`] interpretation.
pub fn transplant_effective(target: &[u8], donor: &[u8]) -> Result<Vec<u8>, Error> {
    let required = observe(donor)?;
    if observe(target)? == required {
        return Ok(target.to_vec());
    }
    let before = bind(target)?;
    let changed = if before.convention == Convention::WholeWord && !before.packed_shape {
        callers::select_bytes(target, donor, required == Convention::PackedBytes)?
    } else {
        transplant(target, donor, None)?
    };
    // A copied reader alone cannot reproduce bytes selected by the donor's caller.
    if observe(&changed)? != required {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

#[cfg(test)]
mod tests;
