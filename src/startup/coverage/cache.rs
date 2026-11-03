//! Native bulk reader and byte accessor. The loop copies words 0x0060–0x009F
//! into 128 RAM bytes; it does not enforce a fixed value. Consumers and cache
//! writers must be audited separately before making an acceptance claim.
use super::CallKind;
use crate::image::layout::Observation;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
pub(super) struct Shape {
    pub bytes: &'static [u8],
    pub call: usize,
    pub ram: [usize; 2],
    pub argument_register: u8,
}
impl Shape {
    fn bind(&self, bytes: &[u8], getter: u32) -> Option<u32> {
        if bytes.len() != self.bytes.len() {
            return None;
        }
        let ram = u32::from_be_bytes(bytes[self.ram[0]..self.ram[0] + 4].try_into().unwrap());
        ram.checked_add(127)?;
        let valid = bytes.iter().zip(self.bytes).enumerate().all(|(i, (a, b))| {
            if (self.call + 1..self.call + 4).contains(&i) {
                *a == getter.to_be_bytes()[i - self.call]
            } else if let Some(&r) = self.ram.iter().find(|&&r| (r..r + 4).contains(&i)) {
                *a == ram.to_be_bytes()[i - r]
            } else {
                a == b
            }
        });
        valid.then_some(ram)
    }
}
/// A leaf byte accessor bound to the exact RAM base written by the bulk loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accessor {
    /// Decoded Normal entry offset.
    pub offset: usize,
    /// Low byte of the native R0 or R1 argument selects a cache byte.
    pub argument_register: u8,
}
/// Complete bulk loop with its native RAM base and matching accessor leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// Decoded Normal loop offset.
    pub offset: usize,
    /// Exact getter call offset inside the loop.
    pub getter_call: usize,
    /// Runtime RAM base, not persistent flash placement.
    pub ram_base: u32,
    /// Complete bound accessor leaves; empty does not mean no consumers exist.
    pub accessors: Vec<Accessor>,
}
const R0: &[u8] = &[0x0c, 0x89, 0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28];
const R1: &[u8] = &[0x1a, 0x80, 0x0c, 0x98, 0x78, 0, 0x6a, 0x28];
/// Recognize full fixed-count bulk loops and their byte accessors in stored
/// Normal. All branch/count operands and both RAM destinations must match.
/// This establishes data placement only, not startup-value acceptance.
/// More than one bound loop is reported as conflicting.
pub fn discover(normal: &[u8]) -> Observation<Vec<Block>> {
    let refs = match super::references(normal) {
        Observation::Known(r) => r,
        Observation::Unresolved(r) => return Observation::Unresolved(r),
        Observation::Conflicting => return Observation::Conflicting,
    };
    let regions = crate::image::regions(normal).expect("stored references");
    let mut bound = Vec::new();
    for call in refs.calls.iter().filter(|c| c.kind == CallKind::Absolute) {
        for shape in super::cache_shapes::SHAPES
            .iter()
            .filter(|s| s.argument_register == refs.argument_register)
        {
            let Some(at) = call.offset.checked_sub(shape.call) else {
                continue;
            };
            let Some(bytes) = normal.get(at..at + shape.bytes.len()) else {
                continue;
            };
            let Some(ram_base) = shape.bind(bytes, refs.getter) else {
                continue;
            };
            if !regions.stored.iter().any(|r| {
                let start = r.as_ptr() as usize - normal.as_ptr() as usize;
                at >= start && at + bytes.len() <= start + r.len()
            }) {
                continue;
            }
            bound.push((at, call.offset, ram_base));
            // Every audited image binds exactly one bulk loop. Several are a
            // conflicting contract; stop before any per-block image pass.
            if bound.len() > 1 {
                return Observation::Conflicting;
            }
        }
    }
    let blocks = bound
        .into_iter()
        .map(|(offset, getter_call, ram_base)| Block {
            offset,
            getter_call,
            ram_base,
            accessors: scan_accessors(normal, &regions.stored)
                .remove(&ram_base)
                .unwrap_or_default(),
        })
        .collect();
    Observation::Known(blocks)
}
/// One pass over stored Normal collecting every accessor leaf keyed by the RAM
/// base it reads, in physical order.
fn scan_accessors(normal: &[u8], stored: &[&[u8]]) -> BTreeMap<u32, Vec<Accessor>> {
    #[cfg(test)]
    tests::ACCESSOR_SCANS.with(|c| c.set(c.get() + 1));
    let mut accessors: BTreeMap<u32, Vec<Accessor>> = BTreeMap::new();
    for r in stored {
        let base = r.as_ptr() as usize - normal.as_ptr() as usize;
        for local in (base & 1..r.len()).step_by(2) {
            for (register, head) in [(0, R0), (1, R1)] {
                let Some(bytes) = r.get(local..local + head.len() + 6) else {
                    continue;
                };
                if register == 1 && local >= 2 && r[local - 2..local] == [0x0c, 0x89] {
                    continue;
                }
                if bytes[..head.len()] == *head && bytes[head.len() + 4..] == [0x54, 0x70] {
                    let ram_base =
                        u32::from_be_bytes(bytes[head.len()..head.len() + 4].try_into().unwrap());
                    accessors.entry(ram_base).or_default().push(Accessor {
                        offset: base + local,
                        argument_register: register,
                    });
                }
            }
        }
    }
    accessors
}
#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    std::thread_local! {
        pub(super) static ACCESSOR_SCANS: Cell<usize> = const { Cell::new(0) };
    }
    #[test]
    fn more_than_one_bound_loop_conflicts_before_any_accessor_scan() {
        let mut raw = alloc::vec![0xff;0x5000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let shape = &super::super::cache_shapes::SHAPES[0];
        for at in [0x2000, 0x2400] {
            raw[at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
            raw[at + shape.call + 1..at + shape.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
            for r in shape.ram {
                raw[at + r..at + r + 4].copy_from_slice(&0xa01000u32.to_be_bytes());
            }
        }
        let mut leaf = R0.to_vec();
        leaf.extend_from_slice(&0xa01000u32.to_be_bytes());
        leaf.extend_from_slice(&[0x54, 0x70]);
        raw[0x3000..0x3000 + leaf.len()].copy_from_slice(&leaf);
        ACCESSOR_SCANS.with(|c| c.set(0));
        assert!(matches!(discover(&raw), Observation::Conflicting));
        assert_eq!(ACCESSOR_SCANS.with(Cell::get), 0);
        // Downstream consumers stop before any per-block image pass.
        assert!(matches!(
            super::super::cache_helpers::discover(&raw),
            Observation::Conflicting
        ));
        assert!(matches!(
            super::super::cache_rom::discover(&raw),
            Observation::Conflicting
        ));
        assert!(matches!(
            super::super::cache_flow::discover_direct(&raw),
            Observation::Conflicting
        ));
        assert!(matches!(
            super::super::cache_indices::discover(&raw),
            Observation::Conflicting
        ));
        // A single bound loop still binds its accessor with one scan.
        raw[0x2400..0x2400 + shape.bytes.len()].fill(0xff);
        ACCESSOR_SCANS.with(|c| c.set(0));
        let Observation::Known(blocks) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(ACCESSOR_SCANS.with(Cell::get), 1);
        assert_eq!(
            blocks
                .iter()
                .map(|b| (b.offset, b.ram_base, b.accessors.clone()))
                .collect::<Vec<_>>(),
            alloc::vec![(
                0x2000,
                0xa01000,
                alloc::vec![Accessor {
                    offset: 0x3000,
                    argument_register: 0
                }]
            )]
        );
    }
    #[test]
    fn every_loop_instruction_and_operand_relationship_is_required() {
        for shape in super::super::cache_shapes::SHAPES {
            let mut bytes = shape.bytes.to_vec();
            let getter = 0x411000u32;
            let ram = 0xa01000u32;
            bytes[shape.call + 1..shape.call + 4].copy_from_slice(&getter.to_be_bytes()[1..]);
            for r in shape.ram {
                bytes[r..r + 4].copy_from_slice(&ram.to_be_bytes());
            }
            assert_eq!(shape.bind(&bytes, getter), Some(ram));
            for i in 0..bytes.len() {
                bytes[i] ^= 1;
                assert_eq!(shape.bind(&bytes, getter), None, "byte {i}");
                bytes[i] ^= 1;
            }
        }
    }
    #[test]
    fn accessor_must_read_the_same_base_and_return_without_a_gate() {
        let mut raw = alloc::vec![0xff;0x5000];
        crate::image::layout::install_test_layout(&mut raw, 0x1000);
        let shape = &super::super::cache_shapes::SHAPES[0];
        let at = 0x2000;
        raw[at..at + shape.bytes.len()].copy_from_slice(shape.bytes);
        raw[at + shape.call + 1..at + shape.call + 4].copy_from_slice(&[0x41, 0x10, 0]);
        for r in shape.ram {
            raw[at + r..at + r + 4].copy_from_slice(&0xa01000u32.to_be_bytes());
        }
        let mut leaf = R0.to_vec();
        leaf.extend_from_slice(&0xa01000u32.to_be_bytes());
        leaf.extend_from_slice(&[0x54, 0x70]);
        raw[0x3000..0x3000 + leaf.len()].copy_from_slice(&leaf);
        let Observation::Known(blocks) = discover(&raw) else {
            panic!("fixture")
        };
        assert_eq!(blocks[0].accessors.len(), 1);
        for i in 0..leaf.len() {
            raw[0x3000 + i] ^= 1;
            let Observation::Known(blocks) = discover(&raw) else {
                panic!("fixture")
            };
            // Corrupting the R0-to-R1 copy can leave a valid standalone R1 leaf;
            // it must never retain the original R0 contract.
            assert!(!blocks[0]
                .accessors
                .iter()
                .any(|a| a.offset == 0x3000 && a.argument_register == 0));
            raw[0x3000 + i] ^= 1;
        }
    }
}
