//! Native M7900 initializer's bounded CPU I/O configuration block.
use crate::image::layout::{Observation, Unresolved};

const BASE: usize = 0x3800;
const ENTRY: usize = 0x10000;
// The entire straight-line block through CLI. The following program is outside
// this observation, and these writes alone do not establish reset reachability.
const BLOCK: &[u8] = &[
    0xb9, 0x30, 0x7d, 0, 0xb9, 0x20, 0x7e, 0, 0xb9, 0x20, 0x7f, 0, 0x44, 0xce, 0x75, 0, 0xce, 0x76,
    0, 0xce, 0x78, 0, 0xce, 0x7a, 0, 0xce, 0x7b, 0, 0xce, 0x7c, 0, 0x05, 0xa5, 0x95, 0x66, 0xff,
    0xf8, 0x85, 0xb5, 0x15,
];

/// Configuration established by a complete bounded native instruction block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// Ordered sixteen-bit CPU I/O destinations and immediate byte values.
    pub writes: [(u16, u8); 3],
    /// Native CPU start and exclusive end of the observed straight-line block.
    pub source_span: (u32, u32),
}

/// Recognize the CPU I/O block in decoded Normal's native 0x3800 mapping.
///
/// Every instruction is bound, including the subsequent peripheral clears and
/// interrupt-status setup. Addresses and values of the three MOVMB instructions
/// are native operands. A miss remains unresolved, including external-resident
/// startup variants; it never establishes that initialization is inapplicable.
pub fn discover(normal: &[u8]) -> Observation<Evidence> {
    let missing = || Observation::Unresolved(Unresolved::ReaderNotRecognized);
    let Some(code) = normal.get(ENTRY - BASE..ENTRY - BASE + BLOCK.len()) else {
        return missing();
    };
    if !code
        .iter()
        .zip(BLOCK)
        .enumerate()
        .all(|(i, (a, b))| a == b || matches!(i, 1..=3 | 5..=7 | 9..=11))
    {
        return missing();
    }
    let writes = [0usize, 4, 8].map(|at| {
        (
            u16::from_le_bytes([code[at + 2], code[at + 3]]),
            code[at + 1],
        )
    });
    // MOVMB's operand may name any native address, but this observer is for the
    // CPU's three I/O ports. Relocation elsewhere is not silently called I/O.
    if writes
        .iter()
        .any(|(address, _)| !(0x7d..=0x7f).contains(address))
        || writes[0].0 == writes[1].0
        || writes[0].0 == writes[2].0
        || writes[1].0 == writes[2].0
    {
        return missing();
    }
    Observation::Known(Evidence {
        writes,
        source_span: (ENTRY as u32, (ENTRY + BLOCK.len()) as u32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    fn fixture() -> Vec<u8> {
        let mut normal = vec![0xff; ENTRY - BASE + BLOCK.len()];
        normal[ENTRY - BASE..].copy_from_slice(BLOCK);
        normal
    }

    #[test]
    fn native_io_values_are_preserved_without_claiming_reset_reachability() {
        let mut normal = fixture();
        let Observation::Known(original) = discover(&normal) else {
            panic!("fixture not recognized")
        };
        assert_eq!(original.writes, [(0x7d, 0x30), (0x7e, 0x20), (0x7f, 0x20)]);
        for (n, at) in [1usize, 5, 9].into_iter().enumerate() {
            normal[ENTRY - BASE + at] ^= 1;
            let Observation::Known(changed) = discover(&normal) else {
                panic!("native scalar lost")
            };
            assert_ne!(changed.writes[n], original.writes[n]);
            normal[ENTRY - BASE + at] ^= 1;
        }
        normal.swap(ENTRY - BASE + 2, ENTRY - BASE + 6);
        let Observation::Known(changed) = discover(&normal) else {
            panic!("port order lost")
        };
        assert_eq!(changed.writes[0].0, 0x7e);
        assert_eq!(changed.writes[1].0, 0x7d);
    }

    #[test]
    fn instruction_mutation_and_external_startup_are_unresolved() {
        let mut normal = fixture();
        for at in 0..BLOCK.len() {
            if matches!(at, 1..=3 | 5..=7 | 9..=11) {
                continue;
            }
            normal[ENTRY - BASE + at] ^= 1;
            assert!(
                !matches!(discover(&normal), Observation::Known(_)),
                "instruction {at}"
            );
            normal[ENTRY - BASE + at] ^= 1;
        }
        for at in [3usize, 7, 11] {
            normal[ENTRY - BASE + at] = 1;
            assert!(!matches!(discover(&normal), Observation::Known(_)));
            normal[ENTRY - BASE + at] = 0;
        }
        normal[ENTRY - BASE + 6] = 0x7d;
        assert!(
            !matches!(discover(&normal), Observation::Known(_)),
            "duplicate port"
        );
        normal[ENTRY - BASE + 6] = 0x7e;
        normal[ENTRY - BASE + 2] = 0x7c;
        assert!(
            !matches!(discover(&normal), Observation::Known(_)),
            "port below 7d"
        );
        normal[ENTRY - BASE + 2] = 0x7d;
        assert!(matches!(discover(&[]), Observation::Unresolved(_)));
        for end in ENTRY - BASE..normal.len() {
            assert!(!matches!(discover(&normal[..end]), Observation::Known(_)));
        }
        normal[ENTRY - BASE..ENTRY - BASE + 4].copy_from_slice(&[0xad, 0x4e, 0x7f, 0x13]);
        assert!(matches!(discover(&normal), Observation::Unresolved(_)));
    }
}
