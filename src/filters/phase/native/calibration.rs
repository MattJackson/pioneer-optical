//! Native interpretation of the unit's existing 0x112/0x113 calibration words.
//! Only reader code changes; no persistent calibration value is copied or written.
use super::*;
use core::ops::Range;

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
#[derive(Debug)]
struct Reader {
    at: usize,
    convention: Convention,
    packed_shape: bool,
    getter: [u8; 3],
}
fn bind(normal: &[u8]) -> Result<Reader, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut found = None;
    for region in &regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        for (packed, template, holes) in [
            (false, WHOLE, &[31usize][..]),
            (true, PACKED, &[43usize, 53][..]),
        ] {
            for at in (start + (start & 1)..start + region.len()).step_by(2) {
                let Some(bytes) = normal
                    .get(at..at + template.len())
                    .filter(|_| at + template.len() <= start + region.len())
                else {
                    continue;
                };
                if !bytes.iter().zip(template).enumerate().all(|(i, (a, b))| {
                    holes.iter().any(|h| (*h..*h + 3).contains(&i))
                        || (packed && (56..58).contains(&i))
                        || a == b
                }) {
                    continue;
                }
                let convention = if packed {
                    match &bytes[56..58] {
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
                });
            }
        }
    }
    found.ok_or(Error::Unresolved)
}
/// Observe only after binding the complete reader and matching getter operands.
pub fn observe(normal: &[u8]) -> Result<Convention, Error> {
    Ok(bind(normal)?.convention)
}

/// Preserve the installed storage interpretation at byte-consuming calibration
/// callers by rewriting a copy of target's reader.
/// The original target getter is retained. A native packed reader can preserve
/// whole-word calibration values by removing its high-to-low byte copy. Growing a whole-word
/// reader requires an explicit reservation and a JMP at its original entry.
pub fn rewrite(
    target: &[u8],
    installed: &[u8],
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let required = bind(installed)?.convention;
    let before = bind(target)?;
    let mut changed = target.to_vec();
    if before.convention == required {
        return Ok(changed);
    }
    if before.packed_shape {
        changed[before.at + 56..before.at + 58].copy_from_slice(
            if required == Convention::WholeWord {
                &[0, 0]
            } else {
                &[0x0c, 8]
            },
        );
    } else {
        let space = reservation.ok_or(Error::SpaceRequired)?;
        let regions = crate::image::regions(target).ok_or(Error::Unresolved)?;
        let stored = regions.stored.iter().any(|r| {
            let at = r.as_ptr() as usize - target.as_ptr() as usize;
            space.start >= at && space.end <= at + r.len()
        });
        if space.start & 1 != 0
            || space.end & 1 != 0
            || space.start > space.end
            || space.len() < PACKED.len()
            || !stored
            || (space.start < before.at + WHOLE.len() && before.at < space.end)
            || !target
                .get(space.clone())
                .is_some_and(|b| b.iter().all(|b| *b == 0xff))
        {
            return Err(Error::InvalidSpace);
        }
        let mut program = PACKED.to_vec();
        for at in [43, 53] {
            program[at..at + 3].copy_from_slice(&before.getter);
        }
        let address = 0x410000usize
            .checked_add(space.start)
            .filter(|a| *a <= 0xffffff)
            .ok_or(Error::InvalidSpace)? as u32;
        changed[space.clone()].fill(0);
        changed[space.start..space.start + program.len()].copy_from_slice(&program);
        changed[before.at..before.at + 4].copy_from_slice(&[
            0x5a,
            address.to_be_bytes()[1],
            address.to_be_bytes()[2],
            address.to_be_bytes()[3],
        ]);
    }
    if observe(&changed)? != required {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

#[cfg(test)]
mod tests;
