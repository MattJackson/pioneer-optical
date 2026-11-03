//! Normal-only proof of the native M32C D9 startup requirement.
//!
//! This establishes a getter comparison and the rejection transfer's intent.
//! It does not identify a write recipe or assert the behavior of the boot ROM.
use crate::image::layout::{Observation, Unresolved};
use alloc::vec::Vec;
#[path = "m32c_shapes.rs"]
mod shapes;
use shapes::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Span {
    pub offset: usize,
    pub bytes: usize,
    pub address: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DescriptorProof {
    pub table_address: u32,
    pub entry: Span,
    pub word: u16,
}

/// Coordinates are evidence, and must not participate in value comparison.
#[derive(Clone, Debug)]
pub(super) struct Evidence {
    pub parameter: u16,
    pub accepted_value: u16,
    pub base: u32,
    pub gate: Span,
    pub getter: Span,
    pub resolver: Span,
    pub getter_reader: Span,
    pub lower_reader: Span,
    pub startup_callers: Vec<Span>,
    pub reject: Span,
    pub reject_transfer: u32,
    pub descriptor: Option<DescriptorProof>,
}

fn le24(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], 0])
}

fn relative(body: &[u8], at: usize) -> Option<usize> {
    let b = body.get(at..at.checked_add(3)?)?;
    if b[0] != 0xcf {
        return None;
    }
    at.checked_add_signed(1 + isize::from(i16::from_le_bytes([b[1], b[2]])))
}

fn matches(body: &[u8], at: usize, shape: &[u8], operands: &[(usize, usize)]) -> bool {
    let Some(bytes) = at
        .checked_add(shape.len())
        .and_then(|end| body.get(at..end))
    else {
        return false;
    };
    bytes.iter().zip(shape).enumerate().all(|(i, (a, b))| {
        a == b
            || operands
                .iter()
                .any(|&(start, len)| (start..start + len).contains(&i))
    })
}

fn span(base: u32, offset: usize, bytes: usize) -> Option<Span> {
    let address = base.checked_add(u32::try_from(offset).ok()?)?;
    if u64::from(address).checked_add(bytes as u64)? > 0x1000000 {
        return None;
    }
    Some(Span {
        offset,
        bytes,
        address,
    })
}

fn offset(body: &[u8], base: u32, address: u32, bytes: usize) -> Option<usize> {
    if u64::from(address).checked_add(bytes as u64)? > 0x1000000 {
        return None;
    }
    let at = usize::try_from(address.checked_sub(base)?).ok()?;
    body.get(at..at.checked_add(bytes)?)?;
    Some(at)
}

// Native startup calls the gate immediately before installing a callback and
// clearing the startup flag. These RAM/code operands relocate independently.
fn callers(body: &[u8], base: u32, gate: usize) -> Vec<Span> {
    let mut result = Vec::new();
    for at in 4..gate.min(body.len().saturating_sub(16)) {
        if relative(body, at) != Some(gate)
            || body[at - 4] != 0xcd
            || body.get(at + 3..at + 5) != Some(&[0xb6, 0xf1])
            || body.get(at + 10..at + 16) != Some(&[0x00, 0xb6, 0xf1, 0x0e, 0x20, 0x3a])
                && body.get(at + 10..at + 16) != Some(&[0x00, 0xb6, 0xf1, 0x0e, 0x20, 0x76])
                && body.get(at + 10..at + 16) != Some(&[0x00, 0xb6, 0xf1, 0x0e, 0x20, 0x96])
                && body.get(at + 10..at + 16) != Some(&[0x00, 0xb6, 0xf1, 0x0f, 0x20, 0x97])
        {
            continue;
        }
        let ram = u16::from_le_bytes([body[at + 5], body[at + 6]]);
        if !(0x2000..0x8000).contains(&ram)
            || offset(body, base, le24(&body[at - 3..at]), 1).is_none()
            || offset(body, base, le24(&body[at + 7..at + 10]), 1).is_none()
        {
            continue;
        }
        if let Some(s) = span(base, at - 4, 20) {
            result.push(s);
        }
    }
    result
}

fn bind(
    body: &[u8],
    gate: usize,
    getter: usize,
    getter_shape: &[u8],
    descriptor: bool,
) -> Option<Evidence> {
    let absolute_getter = le24(body.get(gate + 4..gate + 7)?);
    let base = absolute_getter.checked_sub(u32::try_from(getter).ok()?)?;
    // A serialized Normal may include a tail beyond the CPU's mapped window.
    // Bound every actual proof span/reference instead of treating that tail as
    // mapped code or rejecting an otherwise fully contained native graph.
    let resolver_call = getter + if descriptor { 22 } else { 21 };
    let resolver = relative(body, resolver_call)?;
    let resolver_shape = if descriptor {
        DESCRIPTOR_RESOLVER
    } else if getter_shape == OLD_RANGE_GETTER {
        OLD_RANGE_RESOLVER
    } else {
        RANGE_RESOLVER
    };
    if !matches(
        body,
        resolver,
        resolver_shape,
        if descriptor { &[(132, 3)] } else { &[] },
    ) {
        return None;
    }
    // The range forms completely bind the D0..11F arm, its selected FFAA20
    // region, its success path and the unsupported-ID return. The descriptor
    // form instead reaches the shared indexed descriptor test for D9.
    let descriptor = if descriptor {
        let table = le24(body.get(resolver + 132..resolver + 135)?);
        if le24(body.get(getter + 72..getter + 75)?) != table
            || le24(body.get(getter + 81..getter + 84)?) != table
        {
            return None;
        }
        let entry_address = table.checked_add(0xd9 * 2)?;
        let entry = offset(body, base, entry_address, 2)?;
        let word = u16::from_le_bytes([body[entry], body[entry + 1]]);
        // FFFF means this ID is unsupported, not that its read value is FFFF.
        if word == 0xffff {
            return None;
        }
        Some(DescriptorProof {
            table_address: table,
            entry: span(base, entry, 2)?,
            word,
        })
    } else {
        None
    };
    let reader_operand = getter + if descriptor.is_some() { 47 } else { 46 };
    let reader = offset(
        body,
        base,
        le24(body.get(reader_operand..reader_operand + 3)?),
        11,
    )?;
    // Complete mapped-word reader wrapper and its actual lower read operation.
    // No H8 reader or writer is substituted for either native routine.
    if body.get(reader..reader + 6) != Some(&[0xf8, 0x20, 0xc9, 0x8e, 0xf8, 0xa2])
        || body.get(reader + 9..reader + 11) != Some(&[0x43, 0xdf])
    {
        return None;
    }
    let lower_reader = relative(body, reader + 6)?;
    let lower_shape = [
        RANGE_LOWER_READER,
        OLD_RANGE_LOWER_READER,
        DESCRIPTOR_LOWER_READER,
    ]
    .into_iter()
    .find(|s| matches(body, lower_reader, s, &[]))?;
    let reject = relative(body, gate + 11)?;
    let rejection = [REJECT_0, REJECT_1, REJECT_2, REJECT_3]
        .into_iter()
        .find(|s| matches(body, reject, s, &[]))?;
    let startup_callers = callers(body, base, gate);
    if startup_callers.is_empty() {
        return None;
    }
    Some(Evidence {
        parameter: 0xd9,
        accepted_value: 0xffff,
        base,
        gate: span(base, gate, 15)?,
        getter: span(base, getter, getter_shape.len())?,
        resolver: span(base, resolver, resolver_shape.len())?,
        getter_reader: span(base, reader, 11)?,
        lower_reader: span(base, lower_reader, lower_shape.len())?,
        startup_callers,
        reject: span(base, reject, rejection.len())?,
        reject_transfer: 0xffc014,
        descriptor,
    })
}

/// Bind the full native D9/FFFF startup gate, failing closed on missing evidence.
pub(super) fn discover(normal: &[u8]) -> Observation<Evidence> {
    let mut found = None;
    for (gate, b) in normal.windows(15).enumerate() {
        if b[..4] != [0x05, 0xd9, 0x00, 0xcd]
            || b[7..12] != [0xe9, 0x9f, 0xda, 0x04, 0xcf]
            || b[14] != 0xdf
        {
            continue;
        }
        let mut bound = false;
        for (shape, descriptor, operands) in [
            (RANGE_GETTER, false, &[(46, 3)][..]),
            (OLD_RANGE_GETTER, false, &[(46, 3)][..]),
            (
                DESCRIPTOR_GETTER,
                true,
                &[(23, 2), (47, 3), (72, 3), (81, 3)][..],
            ),
        ] {
            for getter in 0..normal.len().saturating_sub(shape.len() - 1) {
                if normal[getter] != 0xec || !matches(normal, getter, shape, operands) {
                    continue;
                }
                if let Some(evidence) = bind(normal, gate, getter, shape, descriptor) {
                    if found.is_some() {
                        return Observation::Unresolved(Unresolved::AmbiguousReader);
                    }
                    found = Some(evidence);
                    bound = true;
                }
            }
        }
        // A second gate with an unbound caller/reader cannot be dismissed as
        // unused merely because another complete candidate exists.
        if !bound {
            return Observation::Unresolved(Unresolved::ReaderNotRecognized);
        }
    }
    found
        .map(Observation::Known)
        .unwrap_or(Observation::Unresolved(Unresolved::ReaderNotRecognized))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn absolute(b: &mut [u8], at: usize, address: u32) {
        b[at..at + 3].copy_from_slice(&address.to_le_bytes()[..3]);
    }
    fn relative_call(b: &mut [u8], at: usize, target: usize) {
        b[at] = 0xcf;
        let displacement = i16::try_from(target as isize - at as isize - 1).unwrap();
        b[at + 1..at + 3].copy_from_slice(&displacement.to_le_bytes());
    }
    fn fixture(descriptor: bool, old: bool, shift: usize, base: u32) -> Vec<u8> {
        let mut b = vec![0xff; shift + 0x5000];
        let getter = shift + 0x1000;
        let shape = if descriptor {
            DESCRIPTOR_GETTER
        } else if old {
            OLD_RANGE_GETTER
        } else {
            RANGE_GETTER
        };
        b[getter..getter + shape.len()].copy_from_slice(shape);
        let resolver = if descriptor {
            getter + 0x7b8
        } else {
            getter + 0x8d0
        };
        let r = if descriptor {
            DESCRIPTOR_RESOLVER
        } else if old {
            OLD_RANGE_RESOLVER
        } else {
            RANGE_RESOLVER
        };
        b[resolver..resolver + r.len()].copy_from_slice(r);
        if descriptor {
            let table = base + shift as u32 + 0x4000;
            for at in [getter + 72, getter + 81, resolver + 132] {
                absolute(&mut b, at, table);
            }
            b[shift + 0x41b2..shift + 0x41b4].copy_from_slice(&57u16.to_le_bytes());
        }
        absolute(
            &mut b,
            getter + if descriptor { 47 } else { 46 },
            base + shift as u32 + 0x3000,
        );
        let reader = shift + 0x3000;
        b[reader..reader + 11]
            .copy_from_slice(&[0xf8, 0x20, 0xc9, 0x8e, 0xf8, 0xa2, 0xcf, 0, 0, 0x43, 0xdf]);
        relative_call(&mut b, reader + 6, shift + 0x3100);
        let lower = if descriptor {
            DESCRIPTOR_LOWER_READER
        } else if old {
            OLD_RANGE_LOWER_READER
        } else {
            RANGE_LOWER_READER
        };
        b[shift + 0x3100..shift + 0x3100 + lower.len()].copy_from_slice(lower);
        let reject = shift + 0x280;
        b[reject..reject + REJECT_0.len()].copy_from_slice(REJECT_0);
        let gate = shift + 0x200;
        b[gate..gate + 15].copy_from_slice(&[
            0x05, 0xd9, 0, 0xcd, 0, 0, 0, 0xe9, 0x9f, 0xda, 4, 0xcf, 0, 0, 0xdf,
        ]);
        absolute(&mut b, gate + 4, base + getter as u32);
        relative_call(&mut b, gate + 11, reject);
        let caller = shift + 0x100;
        b[caller - 4..caller + 16].copy_from_slice(&[
            0xcd, 0, 0, 0, 0xcf, 0, 0, 0xb6, 0xf1, 0x34, 0x30, 0, 0, 0, 0, 0xb6, 0xf1, 0x0e, 0x20,
            0x3a,
        ]);
        absolute(&mut b, caller - 3, base + shift as u32 + 0x3100);
        absolute(&mut b, caller + 7, base + shift as u32 + 0x3100);
        relative_call(&mut b, caller, gate);
        b
    }

    fn known(b: &[u8]) -> Evidence {
        match discover(b) {
            Observation::Known(e) => e,
            other => panic!("gate not bound: {other:?}"),
        }
    }

    #[test]
    #[ignore = "requires private held Normal corpus cache"]
    fn held_native_first_audited_gate() {
        let home = std::env::var("HOME").expect("HOME for held Normal cache");
        let path = std::path::Path::new(&home).join(".cache/freemkv-startup/corpus/normal/db9be39bb1af27e3661014ce1ea531f92e1ebcad96e9cd282ae36c83ae882204.bin");
        let normal = std::fs::read(path).expect("held APP 1.13 Normal");
        let e = known(&normal);
        assert_eq!((e.parameter, e.accepted_value), (0xd9, 0xffff));
        assert_eq!(e.base, 0xf40000);
        assert_eq!(e.gate.address, 0xf4024a);
        assert_eq!(e.getter.address, 0xf781de);
        assert_eq!(e.resolver.address, 0xf78aae);
        assert_eq!(e.lower_reader.address, 0xf79058);
        assert_eq!(e.lower_reader.bytes, 374);
        assert_eq!(e.reject.address, 0xf40206);
    }

    #[test]
    fn native_forms_bind_only_d9_acceptance_with_complete_coordinates() {
        for (descriptor, old) in [(false, false), (false, true), (true, false)] {
            let e = known(&fixture(descriptor, old, 0, 0xf40000));
            assert_eq!((e.parameter, e.accepted_value), (0xd9, 0xffff));
            assert_eq!(e.getter.address, 0xf41000);
            assert_eq!(e.getter_reader.address, 0xf43000);
            assert_eq!(e.lower_reader.address, 0xf43100);
            assert_eq!(
                e.lower_reader.bytes,
                if descriptor {
                    446
                } else if old {
                    344
                } else {
                    374
                }
            );
            assert_eq!(e.startup_callers.len(), 1);
            assert_eq!(e.reject_transfer, 0xffc014);
            assert_eq!(e.descriptor.is_some(), descriptor);
            if let Some(d) = e.descriptor {
                assert_eq!(d.word, 57);
                assert_eq!(d.entry.address, 0xf441b2);
            }
        }
    }

    #[test]
    fn scalar_changes_and_disconnected_native_edges_fail_closed() {
        for descriptor in [false, true] {
            let original = fixture(descriptor, false, 0, 0xf40000);
            let e = known(&original);
            let mut positions = vec![
                0x201,
                0x208,
                0x209,
                0x20c,
                0x101,
                0x10d,
                0x3000,
                e.getter.offset + 34,
                e.resolver.offset + 1,
                e.reject.offset + e.reject.bytes - 3,
            ];
            // D9 is selected through the bounded D0..11F arm in the range form.
            positions.push(e.resolver.offset + if descriptor { 133 } else { 0x19c + 2 });
            if descriptor {
                positions.push(e.getter.offset + 72);
            }
            for at in positions {
                let mut changed = original.clone();
                changed[at] ^= 1;
                assert!(
                    !matches!(discover(&changed), Observation::Known(_)),
                    "accepted {at:#x}, descriptor={descriptor}"
                );
            }
            if descriptor {
                let mut unsupported = original.clone();
                unsupported[0x41b2..0x41b4].fill(0xff);
                assert!(!matches!(discover(&unsupported), Observation::Known(_)));
            }
            assert!(!matches!(
                discover(&original[..e.resolver.offset + e.resolver.bytes - 1]),
                Observation::Known(_)
            ));
        }
    }

    #[test]
    fn relocation_preserves_semantics_and_rebinds_coordinates() {
        for descriptor in [false, true] {
            let first = known(&fixture(descriptor, false, 0, 0xf40000));
            let moved = known(&fixture(descriptor, false, 0x80, 0xe80000));
            assert_eq!(
                (first.parameter, first.accepted_value),
                (moved.parameter, moved.accepted_value)
            );
            assert_ne!(first.gate, moved.gate);
            assert_eq!(moved.base, 0xe80000);
            let mut changed = fixture(descriptor, false, 0, 0xf40000);
            absolute(
                &mut changed,
                0x1000 + if descriptor { 47 } else { 46 },
                0xfffffe,
            );
            assert!(!matches!(discover(&changed), Observation::Known(_)));
        }
    }

    #[test]
    fn readercallee_mutation_invalidates_known() {
        for (descriptor, old) in [(false, false), (false, true), (true, false)] {
            let original = fixture(descriptor, old, 0, 0xf40000);
            let e = known(&original);
            for at in e.lower_reader.offset..e.lower_reader.offset + e.lower_reader.bytes {
                let mut changed = original.clone();
                changed[at] ^= 1;
                assert!(
                    !matches!(discover(&changed), Observation::Known(_)),
                    "accepted lower reader byte {at:#x}, descriptor={descriptor}, old={old}"
                );
            }
            let mut disconnected = original;
            relative_call(&mut disconnected, e.getter_reader.offset + 6, 0x3900);
            assert!(!matches!(discover(&disconnected), Observation::Known(_)));
        }
    }

    #[test]
    fn duplicate_and_incomplete_second_gates_do_not_select_the_first() {
        let mut b = fixture(false, false, 0, 0xf40000);
        let gate = b[0x200..0x20f].to_vec();
        b[0x220..0x22f].copy_from_slice(&gate);
        relative_call(&mut b, 0x22b, 0x280);
        assert!(!matches!(discover(&b), Observation::Known(_)));
        b[0x11c..0x130].copy_from_slice(&[
            0xcd, 0x00, 0x31, 0xf4, 0xcf, 0, 0, 0xb6, 0xf1, 0x34, 0x30, 0, 0x31, 0xf4, 0, 0xb6,
            0xf1, 0x0e, 0x20, 0x3a,
        ]);
        relative_call(&mut b, 0x120, 0x220);
        assert!(matches!(
            discover(&b),
            Observation::Unresolved(Unresolved::AmbiguousReader)
        ));
    }
}
