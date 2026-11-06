//! Bounded scalar authority for the native five-column DSP table consumer.
//!
//! This is positive consumer evidence, not a numeric-data heuristic. The caller
//! must close inbound references to the returned tables, directories, and RAM
//! pointer cells in both Normal and the paired Kernel before exempting bytes.
//! Exact native instruction images bind one implementation, not image identity.
use alloc::vec::Vec;
use core::ops::Range;

const BASE: usize = 0x410000;
const PROGRAMS: &[(usize, &[u8])] = &[
    (0x4ccf3e, include_bytes!("native_comp/scalar_selector.bin")),
    (0x4f50e6, include_bytes!("native_comp/scalar_caller.bin")),
    (0x573e24, include_bytes!("native_comp/scalar_transfer.bin")),
    (0x573c7e, include_bytes!("native_comp/scalar_sink.bin")),
    (
        0x4f492c,
        include_bytes!("native_comp/scalar_map_reader.bin"),
    ),
];
const MAP_WRITERS: &[(usize, &[u8])] = &[
    (0x4f43e6, include_bytes!("native_comp/scalar_map_init.bin")),
    (
        0x4f446a,
        include_bytes!("native_comp/scalar_map_select.bin"),
    ),
    (
        0x4f4a1a,
        include_bytes!("native_comp/scalar_map_update.bin"),
    ),
];

/// Native consumer evidence; all ranges/slots are Normal file offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableAuthority {
    /// Exact word-array extents, derived from directory pointer and native count.
    pub ranges: Vec<Range<usize>>,
    /// The sole allowed raw pointer slot for each corresponding array.
    pub pointer_slots: Vec<usize>,
    /// Complete selected seven-pointer records, including unrelated fields.
    pub directory_ranges: Vec<Range<usize>>,
    /// Complete selector, caller, word-transfer, MMIO sink and column-map reader.
    pub complete_code_bodies: Vec<Range<usize>>,
    /// Exact initializer/update sequences for the two RAM column-map pointers.
    /// These are proof sites, NOT complete functions or reclaimable code.
    pub map_writer_sites: Vec<Range<usize>>,
    /// Absolute CPU cells whose visible writes must be closed by the caller.
    pub map_pointer_cells: [usize; 2],
}

/// Recognize only the reviewed five-column native data path.
///
/// Selector 4ccf3e writes one seven-pointer record to caller stack+2. Caller
/// 4f50e6 clamps the input column to 0..4 and reads a column-map byte through
/// RAM19a6. The three immutable five-byte maps contain only values0..4. Every
/// visible map initializer/update is bound below; reference closure remains a
/// caller obligation so an unknown writer cannot silently widen this domain.
///
/// Caller stack+0x12/0x18/0x1c/0x20 receives record offsets0/4/8/12 + 2*column. The
/// calls at4f544e/54c2/5466/54da (and equivalent branch alternatives) use
/// row counts15/15/9/9 and stride5. Transfer573e24 reads MOV.W @ER6,E0,
/// increments ER6 by2 five times per row, and terminates after R2 rows.
/// Sink573c7e splits E0 into byte MMIO writes; it never treats E0 as an address.
/// Record slots5/6 are stored to stack+0x28/0x2c at4f51a0..51bc and consumed
/// at4f547e/54f2 (plus branch alternatives) with row count5 and stride5.
/// These arrays in records58e660/58e60c have exact50-byte extents.
/// Selector4cd058 explicitly selects58e60c through the same caller data path.
/// Thus exact table lengths are row_count*5*2, independently of their values.
/// The additional complete reader4f492c reads both RAM map pointers at4972/49a2,
/// fetches only a byte through each, doubles it as a column index, and passes
/// two separate five-row arrays to the same scalar transfer. It does not write
/// either pointer cell or reinterpret the map byte as an absolute address.
pub fn observe(image: &[u8]) -> Option<TableAuthority> {
    let regions = crate::image::regions(image)?;
    let stored = |range: &Range<usize>| {
        regions.stored.iter().any(|bytes| {
            let start = bytes.as_ptr() as usize - image.as_ptr() as usize;
            start <= range.start && range.end <= start + bytes.len()
        })
    };
    let bind = |parts: &[(usize, &[u8])]| -> Option<Vec<Range<usize>>> {
        parts
            .iter()
            .map(|(address, bytes)| {
                let start = address.checked_sub(BASE)?;
                let range = start..start.checked_add(bytes.len())?;
                (stored(&range) && image.get(range.clone())? == *bytes).then_some(range)
            })
            .collect()
    };
    let complete_code_bodies = bind(PROGRAMS)?;
    let map_writer_sites = bind(MAP_WRITERS)?;
    // Exact immutable maps named by all bound writers; identity, 0/1/2 clamp,
    // and 0/1/3 clamp. Do not infer the bound merely from nearby low bytes.
    if image.get(0x5936b2 - BASE..0x5936c1 - BASE)? != [0, 1, 2, 3, 4, 0, 1, 2, 2, 2, 0, 1, 3, 3, 3]
        || !stored(&(0x5936b2 - BASE..0x5936c1 - BASE))
    {
        return None;
    }
    let mut ranges = Vec::new();
    let mut pointer_slots = Vec::new();
    let mut directory_ranges = Vec::new();
    // Only records needed for stream5 and their inbound closure are included.
    // Their addresses are explicit selector operands in the bound program.
    for (record, rows) in [
        (0x58e5d4, &[(0usize, 15usize), (1, 15), (2, 9), (3, 9)][..]),
        (
            0x58e660,
            &[(0usize, 15usize), (1, 15), (2, 9), (3, 9), (5, 5), (6, 5)][..],
        ),
        (0x58e644, &[(0usize, 15usize), (1, 15), (2, 9), (3, 9)][..]),
        (0x58e60c, &[(5usize, 5usize), (6, 5)][..]),
    ] {
        let directory = record - BASE..record - BASE + 7 * 4;
        if !stored(&directory) {
            return None;
        }
        directory_ranges.push(directory);
        for &(column, rows) in rows {
            let slot = record - BASE + column * 4;
            let address = u32::from_be_bytes(image.get(slot..slot + 4)?.try_into().ok()?) as usize;
            let start = address.checked_sub(BASE)?;
            let range = start..start.checked_add(rows * 5 * 2)?;
            if address % 2 != 0
                || !stored(&range)
                || complete_code_bodies
                    .iter()
                    .chain(&map_writer_sites)
                    .any(|code| range.start < code.end && code.start < range.end)
            {
                return None;
            }
            ranges.push(range);
            pointer_slots.push(slot);
        }
    }
    Some(TableAuthority {
        ranges,
        pointer_slots,
        directory_ranges,
        complete_code_bodies,
        map_writer_sites,
        map_pointer_cells: [0x19a6, 0x19aa],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut image = alloc::vec![255;0x1b0000];
        for (address, bytes) in PROGRAMS.iter().chain(MAP_WRITERS) {
            image[address - BASE..address - BASE + bytes.len()].copy_from_slice(bytes);
        }
        image[0x5936b2 - BASE..0x5936c1 - BASE]
            .copy_from_slice(&[0, 1, 2, 3, 4, 0, 1, 2, 2, 2, 0, 1, 3, 3, 3]);
        for (record, addresses) in [
            (0x58e5d4, &[0x5a1c6au32, 0x5a1d00, 0x5a1d96, 0x5a1df0][..]),
            (
                0x58e660,
                &[
                    0x5a2336u32,
                    0x5a23cc,
                    0x5a2462,
                    0x5a24bc,
                    0x5a343e,
                    0x5a2c96,
                    0x5a2cc8,
                ][..],
            ),
            (0x58e644, &[0x5a2ab6u32, 0x5a2b4c, 0x5a2be2, 0x5a2c3c][..]),
            (
                0x58e60c,
                &[
                    0x5a2516u32,
                    0x5a25ac,
                    0x5a2642,
                    0x5a269c,
                    0x5a3470,
                    0x5a2cfa,
                    0x5a2d2c,
                ][..],
            ),
        ] {
            for (index, address) in addresses.iter().enumerate() {
                let at = record - BASE + index * 4;
                image[at..at + 4].copy_from_slice(&address.to_be_bytes());
            }
        }
        image
    }
    #[test]
    fn bounded_native_counts_and_scalar_width() {
        let image = fixture();
        let proof = observe(&image).unwrap();
        assert_eq!(
            proof.ranges.iter().map(|r| r.len()).collect::<Vec<_>>(),
            [150, 150, 90, 90, 150, 150, 90, 90, 50, 50, 150, 150, 90, 90, 50, 50]
        );
        for address in [
            0x4f5101, 0x4f5447, 0x573e34, 0x573e3f, 0x4f4483, 0x5936b4, 0x4f4975, 0x4f49a5,
            0x4f497c, 0x4f5477, 0x4f54eb,
        ] {
            let mut bad = image.clone();
            bad[address - BASE] ^= 1;
            assert!(observe(&bad).is_none(), "{address:x}");
        }
        let mut arbitrary_values = image;
        for range in proof.ranges {
            arbitrary_values[range].fill(0x5c);
        }
        assert!(observe(&arbitrary_values).is_some());
    }

    #[test]
    #[ignore = "requires the exact native Normal corpus"]
    fn actual_stream_five_scalar_evidence() {
        let image = std::fs::read(std::env::var("PIONEER_NATIVE_COMP_NORMAL").unwrap()).unwrap();
        let proof = observe(&image).unwrap();
        // The inbound scan's apparent BMI is also in a native nine-row array.
        assert!(proof
            .ranges
            .iter()
            .any(|r| r.start <= 0x5a2c20 - BASE && 0x5a2c22 - BASE <= r.end));
        for address in [
            0x5a2ca4, 0x5a2ca6, 0x5a2ca8, 0x5a2cd6, 0x5a2cd8, 0x5a2cda, 0x5a2d08, 0x5a2d3a,
        ] {
            assert!(proof
                .ranges
                .iter()
                .any(|r| r.start <= address - BASE && address + 2 - BASE <= r.end));
        }
        let sites = [
            0x5a1cd6, 0x5a1d6c, 0x5a1dc6, 0x5a1e20, 0x5a238e, 0x5a2424, 0x5a2b0e, 0x5a2ba4,
        ];
        for address in sites {
            let at = address - BASE;
            assert!(proof
                .ranges
                .iter()
                .any(|r| r.start <= at && at + 4 <= r.end));
            let candidate = u32::from_be_bytes(image[at..at + 4].try_into().unwrap());
            assert!((0x5c4434..0x5cfe06).contains(&candidate));
        }
    }
}
