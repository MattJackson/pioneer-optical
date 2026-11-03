//! Persistent storage geometry, independent of the parameter-record layout.
//!
//! SAT marker/stride equality is the matrix's geometry projection. It does not
//! establish equal header-validation behavior or portable calibration records.
use super::layout::{Observation, Unresolved};
use alloc::{vec, vec::Vec};
mod h8;
pub use h8::{Addresses, Contract as MarkerContract, Validation};

/// Code-derived SAT storage geometry used in the matrix family key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Geometry {
    /// Header marker and distance between alternative persistent banks.
    MarkerBanks {
        /// Native 32-bit header marker.
        marker: u32,
        /// Distance in bytes between corresponding bank headers.
        stride: u32,
    },
    /// Earlier storage with explicit native bank bases and no version marker.
    NativeBanks {
        /// Native CPU base addresses in selector order.
        bases: [u32; 2],
        /// Distance in bytes between bank bases.
        stride: u32,
    },
}

fn native_view(body: &[u8]) -> Option<Vec<u8>> {
    let regions = super::regions(body)?;
    let mut native = vec![0xff; body.len()];
    for region in regions.stored {
        let start = region.as_ptr() as usize - body.as_ptr() as usize;
        native[start..start + region.len()].copy_from_slice(region);
    }
    Some(native)
}

/// Full marker/address/validation evidence, retained separately from identity.
/// This read-only observation never authorizes a bank conversion.
pub fn marker_contract(normal: &[u8]) -> Observation<MarkerContract> {
    let Some(native) = native_view(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    h8::analyze(&native).map_or(
        Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Known,
    )
}

fn word(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn call(b: &[u8], at: usize) -> Option<u32> {
    let b = b.get(at..at + 4)?;
    (b[0] == 0x5e).then(|| u32::from_be_bytes([0, b[1], b[2], b[3]]))
}

// The exact audited initializer binds the Normal call to its Kernel selector.
// Relocated table and bank addresses are native operands, never package IDs.
fn kernel_pair(normal: &[u8], kernel: &[u8]) -> Option<Geometry> {
    let mut found = None;
    for at in (0..kernel.len().saturating_sub(85)).step_by(2) {
        let b = &kernel[at..at + 86];
        let fixed: &[(usize, &[u8])] = &[
            (0, &[1, 0x10, 0x6d, 0xf4, 0xfa, 0x31, 0x7a, 5]),
            (
                12,
                &[
                    0x0f, 0xd1, 0x1a, 0x80, 0xf8, 8, 0x0a, 0x90, 1, 0, 0x6f, 0x90, 0, 4, 0x0b,
                    0x91, 0x0b, 0x91, 0x1a, 0x0a, 0x46, 0xec, 1, 0, 0x6b, 0xa5,
                ],
            ),
            (42, &[1, 0, 0x6b, 0xa5]),
            (50, &[1, 0, 0x6b, 0xa5]),
            (62, &[0x7a, 4]),
            (68, &[0x7a, 5]),
            (74, &[0x1f, 0xc0, 0x46, 4, 0x79, 0x0d]),
        ];
        if !fixed
            .iter()
            .all(|(p, bytes)| b.get(*p..p + bytes.len()) == Some(*bytes))
        {
            continue;
        }
        let selector = call(b, 58)?;
        if call(b, 82) != Some(selector) {
            continue;
        }
        let offset = selector.checked_sub(0x400000)? as usize;
        let Some(s) = kernel.get(offset..offset + 44) else {
            continue;
        };
        if s[..2] != [0x6b, 0x28]
            || s[6..8] != [0x6b, 0x20]
            || s[12..30]
                != [
                    0x79, 0x28, 0xff, 0xff, 0x47, 0x12, 0x79, 0x20, 0xff, 0xff, 0x47, 4, 0x1d, 8,
                    0x43, 8, 0x7a, 0,
                ]
            || s[34..38] != [0x40, 6, 0x7a, 0]
            || s[42..44] != [0x54, 0x70]
        {
            continue;
        }
        let bases = [word(s, 30)?, word(s, 38)?];
        let stride = bases[1].checked_sub(bases[0])?;
        if !stride.is_power_of_two()
            || bases[0].checked_add(stride)?.checked_sub(2) != word(s, 2)
            || bases[1].checked_add(stride)?.checked_sub(2) != word(s, 8)
            || word(b, 64) != Some(bases[0])
        {
            continue;
        }
        let entry = 0x400000 + at as u32;
        // Complete startup caller suffix: two initialized state bytes followed
        // by three native calls, the final one entering this initializer.
        let linked = (0..normal.len().saturating_sub(19)).step_by(2).any(|p| {
            let n = &normal[p..p + 20];
            n[..4] == [0xfa, 1, 0x6a, 0xaa]
                && call(n, 8).is_some()
                && call(n, 12).is_some()
                && call(n, 16) == Some(entry)
        });
        if !linked {
            continue;
        }
        if found
            .replace(Geometry::NativeBanks { bases, stride })
            .is_some()
        {
            return None;
        }
    }
    found
}

/// Recover SAT bank geometry from decoded Normal and its supplied Kernel.
/// Missing or ambiguous native evidence is unresolved. No data is rewritten.
pub fn discover_sat(normal: &[u8], kernel: Option<&[u8]>) -> Observation<Geometry> {
    let Some(native) = native_view(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut found = Vec::new();
    if let Some(c) = h8::analyze(&native) {
        let stride = match c.addresses {
            Addresses::Fixed(a) => a[1].checked_sub(a[0]),
            Addresses::Capacity {
                when_one: a,
                otherwise: b,
            } => {
                let a = a[1].checked_sub(a[0]);
                (a == b[1].checked_sub(b[0])).then_some(a).flatten()
            }
        };
        if let Some(stride) = stride.filter(|s| *s != 0) {
            found.push(Geometry::MarkerBanks {
                marker: c.magic,
                stride,
            });
        }
    }
    if let Some(h8::Storage::StateHeaders { sequences, .. }) = h8::state(&native) {
        if let (Some(a), Some(b)) = (
            sequences[0].checked_sub(0xfffe),
            sequences[1].checked_sub(0xfffe),
        ) {
            if b.checked_sub(a) == Some(0x10000) {
                found.push(Geometry::NativeBanks {
                    bases: [a, b],
                    stride: 0x10000,
                });
            }
        }
    }
    let consumer = [
        0x5d, 0x60, 0x7a, 2, 0, 0x5d, 0x51, 0x60, 0x7a, 0x20, 0, 0x5c, 0, 0, 0x46, 4, 0x79, 0x0a,
        0, 0x5c, 0x0f, 0xa0, 0x69, 0x21,
    ];
    if (0..native.len().saturating_sub(consumer.len() - 1))
        .step_by(2)
        .any(|p| native[p..p + consumer.len()] == consumer)
    {
        found.push(Geometry::NativeBanks {
            bases: [0x5c0000, 0x5d0000],
            stride: 0x10000,
        });
    }
    if let Some(kernel) = kernel.and_then(native_view) {
        if let Some(g) = kernel_pair(&native, &kernel) {
            found.push(g);
        }
    }
    let Some(first) = found.first() else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    if found.iter().any(|g| g != first) {
        Observation::Conflicting
    } else {
        Observation::Known(*first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn kernel_fixture() -> (Vec<u8>, Vec<u8>) {
        let mut normal = vec![0xff; 0x2000];
        let mut kernel = vec![0xff; 0x10000];
        for (image,at,code) in [
            (&mut normal,0x136,"6a2a0000014247045e418534fa016aaa000012ba5e56fe225e4046565e405f7e"),
            (&mut kernel,0x5f7e,"01106df4fa317a05000012f60fd11a80f8080a9001006f9000040b910b911a0a46ec01006ba50000148201006ba50000148a01006ba5000014865e4046fa7a04007d00007a05007e95e01fc04604790d007d5e4046fa"),
        ] { let code=decode(code); image[at..at+code.len()].copy_from_slice(&code); }
        let selector=decode("6b28007dfffe6b20007efffe7928ffff47127920ffff47041d0843087a00007d000040067a00007e00005470");
        kernel[0x46fa..0x46fa + selector.len()].copy_from_slice(&selector);
        (normal, kernel)
    }
    #[test]
    fn marker_identity_retains_geometry_and_separate_validation_evidence() {
        let mut normal = vec![0xff; 0x3000];
        h8::fixture(&mut normal);
        assert!(matches!(
            discover_sat(&normal, None),
            Observation::Known(Geometry::MarkerBanks {
                marker: 0xfedc4321,
                stride: 0x10000
            })
        ));
        assert!(matches!(
            marker_contract(&normal),
            Observation::Known(MarkerContract {
                validation: Validation::InitializeAndSelect,
                addresses: Addresses::Fixed([0x7dfffa, 0x7efffa]),
                ..
            })
        ));
        // Marker mismatch between initializer and selector invalidates the proof.
        normal[0x180a] ^= 1;
        assert!(!matches!(
            discover_sat(&normal, None),
            Observation::Known(_)
        ));
    }
    #[test]
    fn kernel_geometry_requires_the_normal_call_and_matching_selector() {
        let (normal, kernel) = kernel_fixture();
        let expected = Geometry::NativeBanks {
            bases: [0x7d0000, 0x7e0000],
            stride: 0x10000,
        };
        assert!(
            matches!(discover_sat(&normal,Some(&kernel)), Observation::Known(g) if g==expected)
        );
        assert!(!matches!(
            discover_sat(&normal, None),
            Observation::Known(_)
        ));
        let mut wrong_normal = normal.clone();
        wrong_normal[0x155] ^= 2;
        assert!(!matches!(
            discover_sat(&wrong_normal, Some(&kernel)),
            Observation::Known(_)
        ));
        for offset in [0x5fb8 + 3, 0x5fd0 + 3, 0x46fa, 0x46fa + 5, 0x46fa + 33] {
            let mut wrong = kernel.clone();
            wrong[offset] ^= 2;
            assert!(
                !matches!(discover_sat(&normal, Some(&wrong)), Observation::Known(_)),
                "{offset:x}"
            );
        }
    }
    #[test]
    fn contradictory_native_geometry_and_malformed_comp_are_rejected() {
        let (mut normal, kernel) = kernel_fixture();
        let consumer = decode("5d607a02005d51607a20005c00004604790a005c0fa06921");
        normal[0x300..0x300 + consumer.len()].copy_from_slice(&consumer);
        assert!(matches!(
            discover_sat(&normal, Some(&kernel)),
            Observation::Conflicting
        ));
        normal[0x1000..0x1004].copy_from_slice(b"COMP");
        assert!(!matches!(
            discover_sat(&normal, Some(&kernel)),
            Observation::Known(_)
        ));
    }
}

/// ATA/SCSI storage geometry projected from a recognized native parameter backend.
/// Region payload sizes are retained here; header format, selection and logical
/// domains remain independently compared by the persistent-layout filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeripheralGeometry {
    /// Absolute flash region addresses and payload sizes in native order.
    FlashRecords(Vec<(u32, u32)>),
    /// Inclusive serial mechanical-word range.
    SerialWords {
        /// First native serial word address.
        first: u16,
        /// Last native serial word address, inclusive.
        last: u16,
    },
    /// Two selected serial record sets with an explicit native slot map.
    SerialRecords {
        /// Record-set base word addresses.
        bases: [u16; 2],
        /// Ordered per-slot word offsets.
        slots: [u8; 8],
    },
}

/// Derive the ATA/SCSI geometry projection after native backend recognition.
/// Never use this as a substitute for SAT bank discovery: a SAT parameter area
/// alone does not establish the enclosing bank geometry.
pub fn peripheral_geometry(
    layout: &super::layout::ParameterLayout,
) -> Observation<PeripheralGeometry> {
    use super::layout::{AddressBasis, ParameterLayout};
    let known = match layout {
        ParameterLayout::FlashRecords { regions, .. }
            if regions.len() >= 2
                && regions
                    .iter()
                    .all(|r| r.basis == AddressBasis::Absolute && r.record_bytes != 0) =>
        {
            Some(PeripheralGeometry::FlashRecords(
                regions
                    .iter()
                    .map(|r| (r.address, r.record_bytes))
                    .collect(),
            ))
        }
        ParameterLayout::SerialRange {
            first_word,
            word_count,
            ..
        } => word_count
            .checked_sub(1)
            .and_then(|n| first_word.checked_add(n))
            .map(|last| PeripheralGeometry::SerialWords {
                first: *first_word,
                last,
            }),
        ParameterLayout::SerialSelected { bases, slots, .. } => {
            Some(PeripheralGeometry::SerialRecords {
                bases: *bases,
                slots: *slots,
            })
        }
        _ => None,
    };
    known.map_or(
        Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Known,
    )
}
