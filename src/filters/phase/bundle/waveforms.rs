//! Waveform data normalization for the two recognized native fetch conventions.
//! DSP address direction remains a separate loader convention. This transforms
//! image-resident coefficients only, never the unit's persistent calibration.
/// Complete loader programs and local resources.
pub mod loader;

use super::Loader;

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
