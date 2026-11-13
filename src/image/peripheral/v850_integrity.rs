//! Native flash checksum bound to startup initializer metadata and Kernel code.
use alloc::vec::Vec;
mod shapes {
    // Complete native initializer and boot checksum programs from held disassembly.
    pub(super) const INITIALIZER: &[u8] = &[
        88, 26, 99, 231, 1, 0, 99, 223, 5, 0, 38, 103, 1, 0, 64, 14, 80, 0, 33, 14, 82, 77, 225, 97,
        178, 5, 31, 82, 229, 69, 38, 87, 5, 0, 97, 82, 230, 5, 127, 58, 202, 5, 0, 104, 10, 128, 133,
        13, 97, 58, 166, 61, 231, 81, 134, 61, 7, 110, 255, 255, 7, 128, 6, 62, 8, 0, 196, 82, 199, 81,
        240, 105, 10, 88, 206, 45, 43, 223, 253, 255, 198, 217, 43, 127, 249, 255, 207, 217, 7, 224,
        13, 80, 196, 82, 220, 81, 42, 127, 1, 0, 42, 63, 13, 0, 198, 57, 42, 87, 9, 0, 15, 88, 202,
        121, 230, 121, 211, 5, 251, 89, 185, 5, 31, 82, 229, 21, 224, 81, 231, 13, 95, 82, 11, 72, 65,
        90, 7, 112, 65, 58, 14, 119, 0, 0, 73, 119, 0, 0, 10, 64, 95, 82, 224, 65, 223, 245, 65, 106,
        240, 105, 214, 221, 0, 80, 165, 5, 31, 82, 35, 223, 5, 0, 35, 231, 1, 0, 72, 26, 127, 0,
    ];
    pub(super) const BOOT_CHECKS: &[&[u8]] = &[
        &[
            64, 86, 28, 0, 92, 82, 0, 88, 42, 103, 1, 0, 204, 89, 92, 82, 204, 253, 224, 89, 186, 29,
            196, 7, 8, 0, 42, 6,
        ],
        &[
            64, 86, 28, 0, 92, 82, 0, 88, 42, 103, 1, 0, 204, 89, 92, 82, 204, 253, 224, 89, 154, 29,
            42, 6, 0, 0, 1, 0,
        ],
        &[
            64, 86, 28, 0, 64, 110, 4, 0, 92, 82, 0, 88, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186,
            253, 64, 110, 8, 0, 196, 199, 88, 7, 242, 5, 32, 102, 64, 0, 68, 14, 0, 0, 65, 103, 197,
            128, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186, 253, 64, 110, 8, 0, 196, 199, 88, 7,
            242, 5, 32, 102, 64, 0, 68, 14, 0, 0, 65, 103, 197, 128, 42, 103, 1, 0, 204, 89, 92, 82,
            92, 106, 186, 253, 64, 110, 8, 0, 196, 199, 88, 7, 242, 5, 32, 102, 64, 0, 68, 14, 0, 0,
            65, 103, 197, 128, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186, 253, 196, 199, 88, 7, 242,
            5, 32, 102, 64, 0, 68, 14, 0, 0, 65, 103, 197, 128, 224, 89, 186, 29, 196, 7, 8, 0, 42, 6,
        ],
        &[
            64, 86, 28, 0, 64, 110, 4, 0, 92, 82, 0, 88, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186,
            253, 64, 110, 8, 0, 196, 199, 88, 7, 242, 5, 32, 102, 64, 0, 68, 14, 0, 0, 65, 103, 197,
            128, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186, 253, 64, 110, 8, 0, 196, 199, 88, 7,
            242, 5, 32, 102, 64, 0, 68, 14, 0, 0, 65, 103, 197, 128, 42, 103, 1, 0, 204, 89, 92, 82,
            92, 106, 186, 253, 64, 110, 8, 0, 196, 199, 88, 7, 242, 5, 32, 102, 64, 0, 68, 14, 0, 0,
            65, 103, 197, 128, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186, 253, 196, 199, 88, 7, 242,
            5, 32, 102, 64, 0, 68, 14, 0, 0, 65, 103, 197, 128, 224, 89, 186, 29, 196, 7, 9, 0, 42, 6,
        ],
        &[
            64, 86, 28, 0, 64, 110, 4, 0, 92, 82, 0, 88, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186,
            253, 64, 110, 8, 0, 196, 199, 96, 7, 242, 5, 32, 102, 64, 0, 68, 14, 33, 252, 65, 103, 197,
            144, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186, 253, 64, 110, 8, 0, 196, 199, 96, 7,
            242, 5, 32, 102, 64, 0, 68, 14, 33, 252, 65, 103, 197, 144, 42, 103, 1, 0, 204, 89, 92, 82,
            92, 106, 186, 253, 64, 110, 8, 0, 196, 199, 96, 7, 242, 5, 32, 102, 64, 0, 68, 14, 33, 252,
            65, 103, 197, 144, 42, 103, 1, 0, 204, 89, 92, 82, 92, 106, 186, 253, 196, 199, 96, 7, 242,
            5, 32, 102, 64, 0, 68, 14, 33, 252, 65, 103, 197, 144, 224, 89, 186, 29, 196, 7, 9, 0, 42,
            6,
        ],
    ];
}
const FLASH_END: usize = 0x1c0000;
const NORMAL_BASE: usize = 0x10000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Contract {
    pub checksum: usize,
    pub initializer: usize,
    pub table: usize,
    pub boot: usize,
}
fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn sum(b: &[u8]) -> u32 {
    b.chunks_exact(4).fold(0u32, |s, b| {
        s.wrapping_add(u32::from_le_bytes(b.try_into().unwrap()))
    })
}
pub(super) fn flash_sum(normal: &[u8], kernel: &[u8]) -> Option<u32> {
    if kernel.len() != NORMAL_BASE
        || normal.len() % 4 != 0
        || normal.len() > FLASH_END - NORMAL_BASE
    {
        return None;
    }
    // The native updater erases the unprogrammed tail through FLASH_END.
    let erased_words = (FLASH_END - kernel.len() - normal.len()) / 4;
    Some(
        sum(kernel)
            .wrapping_add(sum(normal))
            .wrapping_sub(erased_words as u32),
    )
}
pub(super) fn discover(normal: &[u8], kernel: &[u8]) -> Option<Contract> {
    if flash_sum(normal, kernel)? != 0 {
        return None;
    }
    let mut boots = Vec::new();
    for shape in shapes::BOOT_CHECKS {
        for (at, b) in kernel.windows(shape.len()).enumerate().step_by(2) {
            if b == *shape && !boots.contains(&at) {
                boots.push(at);
            }
        }
    }
    if boots.len() != 1 {
        return None;
    }
    let mut found = Vec::new();
    for at in (0..normal.len().min(0x200).saturating_sub(11)).step_by(2) {
        if normal.get(at..at + 2) != Some(&[0x26, 6])
            || normal.get(at + 6..at + 8) != Some(&[0x1f, 0x3a])
        {
            continue;
        }
        let Some(table) = word(normal, at + 2).and_then(|v| (v as usize).checked_sub(NORMAL_BASE))
        else {
            continue;
        };
        let Some(initializer) = super::v850_phase::call(normal, at + 8) else {
            continue;
        };
        if normal.get(initializer..initializer + shapes::INITIALIZER.len())
            != Some(shapes::INITIALIZER)
            || normal.get(table..table + 8) != Some(&[0x52, 0x4d, 0x50, 0, 1, 0, 0, 0])
        {
            continue;
        }
        let Some(destination) = word(normal, table + 8) else {
            continue;
        };
        if word(normal, table + 12) != Some(destination)
            || !(0x03ff0000..0x04000000).contains(&destination)
            || word(normal, table + 20) != Some(24)
        {
            continue;
        }
        let Some(length) = word(normal, table + 16) else {
            continue;
        };
        if destination
            .checked_add(length)
            .map_or(true, |end| end > 0x04000000)
        {
            continue;
        }
        let Some(data_end) = table
            .checked_add(24)
            .and_then(|v| v.checked_add(length as usize))
        else {
            continue;
        };
        let Some(aligned_end) = data_end.checked_add(259).map(|v| v & !255) else {
            continue;
        };
        for end in [aligned_end, 0x1af900] {
            let checksum = end - 4;
            if checksum < data_end || end > normal.len() {
                continue;
            }
            if !normal[data_end..checksum]
                .iter()
                .chain(&normal[end..])
                .all(|&b| b == 255)
            {
                continue;
            }
            let contract = Contract {
                checksum,
                initializer,
                table,
                boot: boots[0],
            };
            if !found.contains(&contract) {
                found.push(contract);
            }
        }
    }
    (found.len() == 1).then(|| found.remove(0))
}
pub(super) fn compensate(normal: &mut [u8], kernel: &[u8], proof: &Contract) -> Option<()> {
    let delta = flash_sum(normal, kernel)?;
    let old = word(normal, proof.checksum)?;
    normal
        .get_mut(proof.checksum..proof.checksum + 4)?
        .copy_from_slice(&old.wrapping_sub(delta).to_le_bytes());
    (flash_sum(normal, kernel)? == 0).then_some(())
}

/// Install the startup stub, initializer, metadata table (with `length` data
/// bytes) and the first boot check; returns the contract they describe. The
/// checksum is not compensated.
#[cfg(test)]
pub(super) fn install(normal: &mut [u8], kernel: &mut [u8], length: u32) -> Contract {
    let shape = shapes::BOOT_CHECKS[0];
    kernel[0x1000..0x1000 + shape.len()].copy_from_slice(shape);
    normal[0x100..0x108].copy_from_slice(&[0x26, 6, 0, 4, 1, 0, 0x1f, 0x3a]);
    normal[0x108..0x10c].copy_from_slice(&[0x80, 0xff, 0xf8, 0]);
    normal[0x200..0x200 + shapes::INITIALIZER.len()].copy_from_slice(shapes::INITIALIZER);
    let fields = [0x00504d52u32, 1, 0x03ff8000, 0x03ff8000, length, 24];
    for (i, v) in fields.iter().enumerate() {
        normal[0x400 + 4 * i..0x404 + 4 * i].copy_from_slice(&v.to_le_bytes());
    }
    Contract {
        checksum: ((0x418 + length as usize + 259) & !255) - 4,
        initializer: 0x200,
        table: 0x400,
        boot: 0x1000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn fixture(shape: &[u8]) -> (Vec<u8>, Vec<u8>, Contract) {
        let mut normal = vec![255; 8192];
        let mut kernel = vec![255; NORMAL_BASE];
        kernel[0x1000..0x1000 + shape.len()].copy_from_slice(shape);
        normal[0x100..0x108].copy_from_slice(&[0x26, 6, 0, 4, 1, 0, 0x1f, 0x3a]);
        normal[0x108..0x10c].copy_from_slice(&[0x80, 0xff, 0xf8, 0]);
        normal[0x200..0x200 + shapes::INITIALIZER.len()].copy_from_slice(shapes::INITIALIZER);
        let fields = [0x00504d52u32, 1, 0x03ff8000, 0x03ff8000, 32, 24];
        for (i, v) in fields.iter().enumerate() {
            normal[0x400 + 4 * i..0x404 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        normal[0x418..0x438].fill(0);
        let proof = Contract {
            checksum: 0x4fc,
            initializer: 0x200,
            table: 0x400,
            boot: 0x1000,
        };
        compensate(&mut normal, &kernel, &proof).unwrap();
        (normal, kernel, proof)
    }
    #[test]
    fn metadata_and_complete_native_functions_bind_checksum_field() {
        for shape in shapes::BOOT_CHECKS {
            let (normal, kernel, proof) = fixture(shape);
            assert_eq!(discover(&normal, &kernel), Some(proof.clone()));
            // Retain a valid additive sum while breaking each distinct proof dependency.
            for at in [0x100, 0x108, 0x200, 0x40c, 0x414, 0x440] {
                let mut bad = normal.clone();
                bad[at] ^= 1;
                compensate(&mut bad, &kernel, &proof).unwrap();
                assert_eq!(discover(&bad, &kernel), None, "normal {at:x}");
            }
            let mut invalid_length = normal.clone();
            invalid_length[0x410..0x414].copy_from_slice(&u32::MAX.to_le_bytes());
            compensate(&mut invalid_length, &kernel, &proof).unwrap();
            assert_eq!(discover(&invalid_length, &kernel), None);
            let mut bad_kernel = kernel.clone();
            bad_kernel[0x1000] ^= 1;
            let mut adjusted = normal.clone();
            compensate(&mut adjusted, &bad_kernel, &proof).unwrap();
            assert_eq!(discover(&adjusted, &bad_kernel), None);
            let mut corrupt = normal.clone();
            corrupt[0x800] ^= 1;
            assert_eq!(discover(&corrupt, &kernel), None);
            assert_eq!(discover(&normal, &kernel[..kernel.len() - 4]), None);
        }
    }
    #[test]
    fn flash_sum_matches_an_independent_known_answer() {
        let kernel = vec![0xff; 0x10000];
        let mut normal = vec![0; 0x1000];
        normal[..4].copy_from_slice(&0x01020304u32.to_le_bytes());
        // 0x4000 erased Kernel words, one Normal word, minus the
        // (0x1c0000 - 0x10000 - 0x1000) / 4 words erased through flash end.
        assert_eq!(flash_sum(&normal, &kernel), Some(0x00fb0704));
    }
    #[test]
    fn duplicate_boot_checks_or_candidate_tables_are_not_a_unique_contract() {
        for shape in shapes::BOOT_CHECKS {
            let (normal, mut kernel, proof) = fixture(shape);
            kernel[0x2000..0x2000 + shape.len()].copy_from_slice(shape);
            let mut adjusted = normal.clone();
            compensate(&mut adjusted, &kernel, &proof).unwrap();
            assert_eq!(discover(&adjusted, &kernel), None);
        }
        let (mut normal, kernel, proof) = fixture(shapes::BOOT_CHECKS[0]);
        // A second stub binds a different table whose data also ends at 0x438,
        // so both describe the same checksum field.
        normal[0x110..0x118].copy_from_slice(&[0x26, 6, 0, 3, 1, 0, 0x1f, 0x3a]);
        normal[0x118..0x11c].copy_from_slice(&[0x80, 0xff, 0xe8, 0]);
        let fields = [0x00504d52u32, 1, 0x03ff8000, 0x03ff8000, 0x120, 24];
        for (i, v) in fields.iter().enumerate() {
            normal[0x300 + 4 * i..0x304 + 4 * i].copy_from_slice(&v.to_le_bytes());
        }
        compensate(&mut normal, &kernel, &proof).unwrap();
        assert_eq!(discover(&normal, &kernel), None);
    }
    #[test]
    fn full_length_normal_uses_the_fixed_checksum_end() {
        let (mut normal, kernel, mut proof) = fixture(shapes::BOOT_CHECKS[0]);
        normal[0x4fc..0x500].fill(0xff);
        normal.resize(0x1af900, 0xff);
        proof.checksum = 0x1af8fc;
        compensate(&mut normal, &kernel, &proof).unwrap();
        assert_eq!(discover(&normal, &kernel), Some(proof));
    }
}
