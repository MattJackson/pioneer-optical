//! Native H8 immediate register-write observations used by the matrix.
//! All recognized aligned stores must agree after masking. Missing stores are
//! unresolved, never a zero value or proof of unrestricted startup behavior.
use super::layout::{Observation, Unresolved};
use alloc::vec::Vec;

/// One immediate byte write to a physical short-addressed register.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Write {
    /// Offset in decoded Normal of the defining immediate load.
    pub offset: usize,
    /// Full byte written before applying the matrix projection.
    pub value: u8,
}

/// An agreed masked value plus the individual native writes that establish it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MaskedWrites {
    /// H8 short absolute register address; this is not a RAM slot.
    pub address: u16,
    /// Bits retained by the matrix filter.
    pub mask: u8,
    /// Value after applying `mask` to every recognized write.
    pub value: u8,
    /// All recognized writes; instruction offsets are evidence, not identity.
    pub writes: Vec<Write>,
}

/// Recognize immediate short-address register stores, preserving register identity.
/// This is a bounded native-code observation, not an all-path reachability claim.
pub fn masked_writes(normal: &[u8], address: u16, mask: u8) -> Observation<MaskedWrites> {
    let Some(regions) = super::regions(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut writes = Vec::new();
    for region in regions.stored {
        let origin = region.as_ptr() as usize - normal.as_ptr() as usize;
        for offset in (origin & 1..region.len().saturating_sub(5)).step_by(2) {
            let b = &region[offset..offset + 6];
            if (0xf8..=0xff).contains(&b[0])
                && b[2] == 0x6a
                && (0x88..=0x8f).contains(&b[3])
                && b[0] & 7 == b[3] & 7
                && b[4..6] == address.to_be_bytes()
            {
                writes.push(Write {
                    offset: origin + offset,
                    value: b[1],
                });
            }
        }
        // R1L remains 40 while an intervening R0L load/store writes FE9F.
        if address == 0xfe94 {
            let shared = [
                0xf9, 0x40, 0x6a, 0x89, 0xfe, 0x9d, 0xf8, 1, 0x6a, 0x88, 0xfe, 0x9f, 0x6a, 0x89,
                0xfe, 0x94,
            ];
            for offset in (origin & 1..region.len().saturating_sub(shared.len() - 1)).step_by(2) {
                if region[offset..offset + shared.len()] == shared {
                    writes.push(Write {
                        offset: origin + offset,
                        value: 0x40,
                    });
                }
            }
        }
    }
    let Some(first) = writes.first() else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let value = first.value & mask;
    if writes.iter().any(|w| w.value & mask != value) {
        return Observation::Conflicting;
    }
    writes.sort_by_key(|w| w.offset);
    Observation::Known(MaskedWrites {
        address,
        mask,
        value,
        writes,
    })
}

/// SAT1/SAT9 startup initialization observation; SAT8 uses input predicates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Startup {
    /// E46B bits zero and four, including native write evidence.
    Register(MaskedWrites),
    /// Complete older initialization program reached through the early call chain.
    LegacyProgram {
        /// Decoded Normal offset of the complete initializer.
        initializer: usize,
        /// Decoded Normal offset of the early wrapper.
        wrapper: usize,
    },
}

const LEGACY: &[u8] = &[
    0xf9, 0x01, 0x6a, 0x89, 0xe4, 0x30, 0xf9, 0x02, 0x6a, 0x89, 0xe4, 0x31, 0xf9, 0x0c, 0x6a, 0x89,
    0xe4, 0x32, 0xf8, 0x08, 0x6a, 0x88, 0xe4, 0x33, 0xf9, 0x02, 0x6a, 0x89, 0xe4, 0x37, 0xf9, 0x01,
    0x6a, 0x89, 0xe4, 0x38, 0x6a, 0x89, 0xe4, 0x39, 0xf8, 0x36, 0x6a, 0x88, 0xe4, 0x3a, 0xf8, 0x15,
    0x6a, 0x88, 0xe4, 0x3b, 0x6a, 0x89, 0xe4, 0x3c, 0xf8, 0x04, 0x6a, 0x88, 0xe4, 0x3d, 0xf8, 0x0d,
    0x6a, 0x88, 0xe4, 0x3e, 0x18, 0x99, 0x6a, 0x89, 0xe4, 0x40, 0x6a, 0x89, 0xe4, 0x41, 0x6a, 0x89,
    0xe4, 0x42, 0x6a, 0x89, 0xe4, 0x44, 0xf8, 0x4c, 0x6a, 0x88, 0xe4, 0x45, 0xf8, 0x29, 0x6a, 0x88,
    0xe4, 0x46, 0xf9, 0x0c, 0x6a, 0x89, 0xe4, 0x47, 0x6a, 0x18, 0xe4, 0x4b, 0x70, 0x00, 0xf9, 0x01,
    0x6a, 0x89, 0xe4, 0x4c, 0xf9, 0x02, 0x6a, 0x89, 0xe4, 0x4d, 0xf9, 0x0c, 0x6a, 0x89, 0xe4, 0x4e,
    0xf8, 0x0b, 0x6a, 0x88, 0xe4, 0x4f, 0x18, 0x99, 0x6a, 0x89, 0xe4, 0x53, 0x6a, 0x89, 0xe4, 0x54,
    0xf8, 0x4c, 0x6a, 0x88, 0xe4, 0x55, 0xf8, 0x29, 0x6a, 0x88, 0xe4, 0x56, 0xf8, 0x15, 0x6a, 0x88,
    0xe4, 0x57, 0xf9, 0x01, 0x6a, 0x89, 0xe4, 0x58, 0xf9, 0x02, 0x6a, 0x89, 0xe4, 0x59, 0xf9, 0x01,
    0x6a, 0x89, 0xe4, 0x5a, 0xf8, 0x11, 0x6a, 0x88, 0xe4, 0x5b, 0x6a, 0x89, 0xe4, 0x5f, 0x6a, 0x18,
    0xe4, 0x5e, 0x72, 0x00, 0x18, 0x99, 0x6a, 0x89, 0xe4, 0x60, 0xf8, 0x4d, 0x6a, 0x88, 0xe4, 0x61,
    0xf9, 0x02, 0x6a, 0x89, 0xe4, 0x62, 0xf8, 0x05, 0x6a, 0x88, 0xe4, 0x63, 0xf9, 0x01, 0x6a, 0x89,
    0xe4, 0x67, 0x54, 0x70,
];

fn call(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at + 4)?;
    (b[0] == 0x5e).then(|| u32::from_be_bytes([0, b[1], b[2], b[3]]))
}

/// Extract E46B projection or the exact earlier initialization program.
/// The legacy program is a distinct typed value, not an invented E46B byte.
pub fn startup(normal: &[u8]) -> Observation<Startup> {
    let Some(regions) = super::regions(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut legacy = None;
    if let Some(wrapper) = call(normal, 0xd0)
        .and_then(|v| v.checked_sub(0x410000))
        .map(|v| v as usize)
    {
        if wrapper & 1 == 0 {
            if let Some(initializer) = call(normal, wrapper + 0x20)
                .and_then(|v| v.checked_sub(0x410000))
                .map(|v| v as usize)
            {
                if initializer & 1 == 0
                    && normal.get(initializer..initializer + LEGACY.len()) == Some(LEGACY)
                {
                    let stored = |at: usize, len: usize| {
                        regions.stored.iter().any(|r| {
                            let start = r.as_ptr() as usize - normal.as_ptr() as usize;
                            at >= start && at + len <= start + r.len()
                        })
                    };
                    if stored(0xd0, 4)
                        && stored(wrapper + 0x20, 4)
                        && stored(initializer, LEGACY.len())
                    {
                        legacy = Some(Startup::LegacyProgram {
                            initializer,
                            wrapper,
                        });
                    }
                }
            }
        }
    }
    match (legacy, masked_writes(normal, 0xe46b, 0x11)) {
        (Some(_), Observation::Known(_) | Observation::Conflicting) => Observation::Conflicting,
        (Some(program), _) => Observation::Known(program),
        (None, Observation::Known(value)) => Observation::Known(Startup::Register(value)),
        (None, Observation::Conflicting) => Observation::Conflicting,
        _ => Observation::Unresolved(Unresolved::ReaderNotRecognized),
    }
}

/// FE94 bit seven; the full writes remain available as supporting evidence.
pub fn host(normal: &[u8]) -> Observation<MaskedWrites> {
    masked_writes(normal, 0xfe94, 0x80)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn masks_preserve_full_writes_and_reject_disagreement() {
        let mut normal = vec![0xff; 64];
        normal[0..6].copy_from_slice(&[0xf8, 0x80, 0x6a, 0x88, 0xfe, 0x94]);
        normal[16..22].copy_from_slice(&[0xf9, 0xc0, 0x6a, 0x89, 0xfe, 0x94]);
        let Observation::Known(value) = host(&normal) else {
            panic!();
        };
        assert_eq!(value.value, 0x80);
        assert_eq!(value.writes.len(), 2);
        assert_eq!(value.writes[1].value, 0xc0);
        normal[17] = 0x40;
        assert!(matches!(host(&normal), Observation::Conflicting));
        normal[19] = 0x88; // R1L immediate must not bind an R0L store.
        let Observation::Known(value) = host(&normal) else {
            panic!();
        };
        assert_eq!(value.writes.len(), 1);
    }
    #[test]
    fn startup_register_keeps_both_masked_e46b_bits() {
        for (immediate, expected) in [(0x11, 0x11), (0x01, 0x01), (0xee, 0)] {
            let mut raw = vec![0xff; 64];
            raw[..6].copy_from_slice(&[0xf8, immediate, 0x6a, 0x88, 0xe4, 0x6b]);
            assert!(
                matches!(
                    startup(&raw),
                    Observation::Known(Startup::Register(MaskedWrites {
                        address: 0xe46b,
                        mask: 0x11,
                        value,
                        ..
                    })) if value == expected
                ),
                "{immediate:#x}"
            );
        }
    }
    #[test]
    fn shared_register_survives_only_the_exact_intervening_sequence() {
        let mut raw = [
            0xf9, 0x40, 0x6a, 0x89, 0xfe, 0x9d, 0xf8, 1, 0x6a, 0x88, 0xfe, 0x9f, 0x6a, 0x89, 0xfe,
            0x94,
        ];
        assert!(
            matches!(host(&raw),Observation::Known(r) if r.value==0 && r.writes[0].value==0x40)
        );
        raw[6] = 0xf9;
        assert!(matches!(host(&raw), Observation::Unresolved(_)));
    }
    #[test]
    fn legacy_initializer_requires_the_early_call_chain_and_complete_body() {
        let mut raw = vec![0xff; 0x900];
        raw[0xd0..0xd4].copy_from_slice(&[0x5e, 0x41, 2, 0]);
        raw[0x220..0x224].copy_from_slice(&[0x5e, 0x41, 4, 0]);
        raw[0x400..0x400 + LEGACY.len()].copy_from_slice(LEGACY);
        assert!(matches!(
            startup(&raw),
            Observation::Known(Startup::LegacyProgram {
                initializer: 0x400,
                wrapper: 0x200
            })
        ));
        for site in [0xd3, 0x223, 0x400 + LEGACY.len() - 1] {
            raw[site] ^= 2;
            assert!(!matches!(startup(&raw), Observation::Known(_)));
            raw[site] ^= 2;
        }
        raw[0x300..0x306].copy_from_slice(&[0xf8, 0, 0x6a, 0x88, 0xe4, 0x6b]);
        assert!(matches!(startup(&raw), Observation::Conflicting));
    }
    #[test]
    fn missing_unaligned_truncated_and_compressed_evidence_is_not_zero() {
        assert!(matches!(host(&[]), Observation::Unresolved(_)));
        assert!(matches!(
            host(&[0xff, 0xf8, 0, 0x6a, 0x88, 0xfe, 0x94]),
            Observation::Unresolved(_)
        ));
        assert!(matches!(
            host(&[0xf8, 0, 0x6a, 0x88, 0xfe]),
            Observation::Unresolved(_)
        ));
        let mut raw = vec![0xff; 0x2000];
        raw[..6].copy_from_slice(&[0xf8, 0, 0x6a, 0x88, 0xfe, 0x94]);
        raw[0x1000..0x1004].copy_from_slice(b"COMP");
        assert!(matches!(host(&raw), Observation::Unresolved(_)));
    }
}
