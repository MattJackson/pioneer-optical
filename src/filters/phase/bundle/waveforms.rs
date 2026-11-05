//! Waveform data normalization for the two recognized native fetch conventions.
//! DSP address direction remains a separate loader convention. This transforms
//! image-resident coefficients only, never the unit's persistent calibration.
/// Complete loader programs and local resources.
pub mod loader;
/// Role-bound image tables and native RAM-pointer initialization.
pub mod resources;

use super::Loader;
use alloc::vec::Vec;

/// A role-bound table/loader stage could not be composed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Native resource roles were not established.
    Resources(resources::Error),
    /// The native loader transformation was unavailable.
    Loader(loader::Error),
    /// A bound table overlaps a program, or the output resources disagree.
    VerificationFailed,
}

/// Transplant OEM waveform data and its original noncomputed loader body.
/// Unlike normalization, this preserves the donor's native fetch convention.
/// Indirect donor loads use relocated read-only pointer cells in the reserved
/// Normal span. Selecting donor tables still requires the caller's live proof;
/// this stage neither reads nor changes a persistent parameter.
pub fn transplant(
    target: &[u8],
    installed: &[u8],
    reservation: Option<core::ops::Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let destination = resources::observe(target).map_err(Error::Resources)?;
    let source = resources::observe(installed).map_err(Error::Resources)?;
    let target_loader = loader::observe(target).map_err(Error::Loader)?;
    let source_loader = loader::observe(installed).map_err(Error::Loader)?;
    let addresses = destination
        .selected
        .coefficients
        .clone()
        .map(|range| 0x410000 + range.start as u32);
    let mut loader_space = reservation.clone();
    let mut pointer_cells = None;
    let tables = match source_loader.tables {
        Some([loader::Table::Literal(_), loader::Table::Literal(_)]) => {
            addresses.map(loader::Table::Literal)
        }
        Some([loader::Table::Pointer(_), loader::Table::Pointer(_)])
            if matches!(
                target_loader.tables,
                Some([loader::Table::Pointer(_), loader::Table::Pointer(_)])
            ) =>
        {
            // Resource observation has resolved these cells, including a bound
            // RAM initializer, to the destination coefficient tables. Both
            // initializer branches receive the donor data below. The owner
            // carries the read-only selection prerequisite.
            target_loader.tables.ok_or(Error::VerificationFailed)?
        }
        Some([loader::Table::Pointer(_), loader::Table::Pointer(_)]) => {
            // Preserve both native indirect-load instructions. Their relocated
            // operands read image-resident pointer cells rather than donor RAM.
            let space = reservation
                .as_ref()
                .ok_or(Error::Loader(loader::Error::SpaceRequired))?;
            let regions = crate::image::regions(target).ok_or(Error::VerificationFailed)?;
            if space.start > space.end
                || space.len() < 8
                || space.start & 1 != 0
                || space.end & 1 != 0
                || !regions.stored.iter().any(|region| {
                    let at = region.as_ptr() as usize - target.as_ptr() as usize;
                    space.start >= at && space.end <= at + region.len()
                })
                || !target
                    .get(space.clone())
                    .is_some_and(|bytes| bytes.iter().all(|b| *b == 0xff))
            {
                return Err(Error::Loader(loader::Error::InvalidSpace));
            }
            // Keep the largest contiguous code remainder. A retired routine
            // can end at either even alignment; only the cells need four-byte
            // alignment. Prefer trailing cells when both layouts fit equally.
            let tail = (space.end - 8) & !3;
            let head = space
                .start
                .checked_add(3)
                .ok_or(Error::Loader(loader::Error::InvalidSpace))?
                & !3;
            let trailing = (tail >= space.start).then_some((tail..tail + 8, space.start..tail));
            let leading = head
                .checked_add(8)
                .filter(|end| *end <= space.end)
                .map(|end| (head..end, end..space.end));
            let (cells, code) = match (trailing, leading) {
                (Some(a), Some(b)) if b.1.len() > a.1.len() => b,
                (Some(a), _) => a,
                (_, Some(b)) => b,
                _ => return Err(Error::Loader(loader::Error::InvalidSpace)),
            };
            let first = 0x410000usize
                .checked_add(cells.start)
                .filter(|address| *address <= 0xfffff8)
                .ok_or(Error::Loader(loader::Error::InvalidSpace))? as u32;
            let bytes = addresses
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>();
            loader_space = Some(code);
            pointer_cells = Some((cells, bytes));
            [
                loader::Table::Pointer(first),
                loader::Table::Pointer(first + 4),
            ]
        }
        _ => return Err(Error::VerificationFailed),
    };
    let mut changed =
        loader::transplant_plain(target, installed, tables, loader_space).map_err(Error::Loader)?;
    if let Some((cells, bytes)) = pointer_cells {
        changed[cells].copy_from_slice(&bytes);
    }
    let mut writes = Vec::new();
    for tables in core::iter::once(&destination.selected).chain(&destination.erased_parameter) {
        for (to, from) in tables.motion.iter().chain(&tables.coefficients).zip(
            source
                .selected
                .motion
                .iter()
                .chain(&source.selected.coefficients),
        ) {
            writes.push((to.clone(), installed[from.clone()].to_vec()));
        }
    }
    let cells: Vec<_> = tables
        .into_iter()
        .filter_map(|table| match table {
            loader::Table::Pointer(address) => {
                let at = address.checked_sub(0x410000)? as usize;
                Some(at..at + 4)
            }
            loader::Table::Literal(_) => None,
        })
        .collect();
    let protected = core::iter::once(&destination.dispatch)
        .chain(&target_loader.spans)
        .chain(destination.initializer.as_ref())
        .chain(reservation.as_ref())
        .chain(&cells)
        .collect::<Vec<_>>();
    for (i, (range, bytes)) in writes.iter().enumerate() {
        if protected
            .iter()
            .any(|program| program.start < range.end && range.start < program.end)
        {
            return Err(Error::VerificationFailed);
        }
        for (other, data) in &writes[..i] {
            if range.start < other.end
                && other.start < range.end
                && (range != other || bytes != data)
            {
                return Err(Error::VerificationFailed);
            }
        }
        changed[range.clone()].copy_from_slice(bytes);
    }
    Ok(changed)
}

/// Convert an eighteen-row coefficient table for the plain paired-word fetch.
///
/// Plain ascending/descending loaders read row i's odd word first and even word
/// second. The wraparound loader instead reads the next row's even word second,
/// with the last coefficient equal to minus the first row's even word. Preserve
/// that exact sequence when its instruction-level special case is removed.
pub fn plain_coefficients(table: &[u8; 72], loader: Loader) -> [u8; 72] {
    let mut plain = *table;
    if loader == Loader::AscendingNegated17 {
        for i in 0..17 {
            plain[4 * i..4 * i + 2].copy_from_slice(&table[4 * (i + 1)..4 * (i + 1) + 2]);
        }
        let first = u16::from_be_bytes([table[0], table[1]]);
        plain[68..70].copy_from_slice(&first.wrapping_neg().to_be_bytes());
    }
    plain
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plain_fetch_preserves_every_wrapped_even_word_and_the_negated_last_coefficient() {
        for first in 0..=u16::MAX {
            let mut table = [0; 72];
            for i in 0..18 {
                table[4 * i..4 * i + 2]
                    .copy_from_slice(&first.wrapping_add(i as u16 * 31).to_be_bytes());
                table[4 * i + 2..4 * i + 4]
                    .copy_from_slice(&first.wrapping_sub(i as u16 * 17).to_be_bytes());
            }
            let plain = plain_coefficients(&table, Loader::AscendingNegated17);
            for i in 0..18 {
                assert_eq!(plain[4 * i + 2..4 * i + 4], table[4 * i + 2..4 * i + 4]);
                let expected = if i == 17 {
                    first.wrapping_neg()
                } else {
                    first.wrapping_add((i + 1) as u16 * 31)
                };
                assert_eq!(
                    u16::from_be_bytes([plain[4 * i], plain[4 * i + 1]]),
                    expected
                );
            }
            assert_eq!(plain_coefficients(&table, Loader::Ascending), table);
            assert_eq!(plain_coefficients(&table, Loader::Descending), table);
        }
    }
}
