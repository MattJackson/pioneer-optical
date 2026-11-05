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

/// Carry installed image-resident waveforms into the target's bound table roles.
/// This stage retains target helper addresses and writes no persistent values.
/// A pointer-selected installed image still requires independent proof of its
/// live non-FFFF selection; observing its initializer does not satisfy that read.
pub fn rewrite(target: &[u8], installed: &[u8]) -> Result<Vec<u8>, Error> {
    let destination = resources::observe(target).map_err(Error::Resources)?;
    let source = resources::observe(installed).map_err(Error::Resources)?;
    let source_loader = loader::observe(installed).map_err(Error::Loader)?;
    let target_loader = loader::observe(target).map_err(Error::Loader)?;
    if destination.selected.coefficients[0] == destination.selected.coefficients[1]
        && installed[source.selected.coefficients[0].clone()]
            != installed[source.selected.coefficients[1].clone()]
    {
        return Err(Error::VerificationFailed);
    }
    let direction = match source_loader.loader {
        Loader::AscendingNegated17 => Loader::Ascending,
        other => other,
    };
    let addresses = destination
        .selected
        .coefficients
        .clone()
        .map(|r| 0x410000 + r.start as u32);
    let mut changed = loader::rewrite(target, direction, addresses, None).map_err(Error::Loader)?;
    let programs = core::iter::once(&destination.dispatch)
        .chain(core::iter::once(&target_loader.program))
        .chain(destination.initializer.as_ref());
    let data: Vec<_> = core::iter::once(&destination.selected)
        .chain(&destination.erased_parameter)
        .flat_map(|tables| tables.motion.iter())
        .chain(&destination.selected.coefficients)
        .collect();
    if programs.into_iter().any(|program| {
        data.iter()
            .any(|span| program.start < span.end && span.start < program.end)
    }) {
        return Err(Error::VerificationFailed);
    }
    for tables in core::iter::once(&destination.selected).chain(&destination.erased_parameter) {
        for (to, from) in tables.motion.iter().zip(&source.selected.motion) {
            changed[to.clone()].copy_from_slice(&installed[from.clone()]);
        }
    }
    for (to, from) in destination
        .selected
        .coefficients
        .iter()
        .zip(&source.selected.coefficients)
    {
        let coefficients: &[u8; 72] = installed[from.clone()]
            .try_into()
            .map_err(|_| Error::VerificationFailed)?;
        changed[to.clone()]
            .copy_from_slice(&plain_coefficients(coefficients, source_loader.loader));
    }
    let after = loader::observe(&changed).map_err(Error::Loader)?;
    if after.loader != direction || after.tables != Some(addresses.map(loader::Table::Literal)) {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
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
        Some([loader::Table::Pointer(_), loader::Table::Pointer(_)]) => {
            // Preserve both native indirect-load instructions. Their relocated
            // operands read image-resident pointer cells rather than donor RAM.
            let space = reservation
                .as_ref()
                .ok_or(Error::Loader(loader::Error::SpaceRequired))?;
            let regions = crate::image::regions(target).ok_or(Error::VerificationFailed)?;
            if space.start > space.end
                || space.len() < 8
                || space.end & 3 != 0
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
            let cells = space.end - 8..space.end;
            let first = 0x410000usize
                .checked_add(cells.start)
                .filter(|address| *address <= 0xfffff8)
                .ok_or(Error::Loader(loader::Error::InvalidSpace))? as u32;
            let bytes = addresses
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .collect::<Vec<_>>();
            loader_space = Some(space.start..cells.start);
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
        for (to, from) in tables.motion.iter().zip(&source.selected.motion) {
            writes.push((to.clone(), installed[from.clone()].to_vec()));
        }
    }
    for (to, from) in destination
        .selected
        .coefficients
        .iter()
        .zip(&source.selected.coefficients)
    {
        writes.push((to.clone(), installed[from.clone()].to_vec()));
    }
    let protected = core::iter::once(&destination.dispatch)
        .chain(core::iter::once(&target_loader.program))
        .chain(destination.initializer.as_ref())
        .chain(reservation.as_ref())
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
