//! Bounded FE09 alternative to the independently accepted FE23 startup value.
//!
//! The complete predicate, range helper, getter and resolver are bound to the
//! same Normal reader graph as the primary selection. This observes native
//! field assembly and branch semantics, with the fixed 0x1058a6 multiplication
//! service abstracted as in the audited assembly; it does not execute that
//! service or establish arbitrary callees' behavior.
use crate::image::layout::{H8ReaderComponent, H8ReaderRole, Observation};
use alloc::{vec, vec::Vec};
#[path = "h8_conditional_shapes.rs"]
mod shapes;
use shapes::*;

const BASE: u32 = 0x410000;
const RANGE_CALLS: [usize; 7] = [288, 326, 374, 396, 418, 440, 468];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ByteHalf {
    Low,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct WordByte {
    pub parameter: u16,
    pub half: ByteHalf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct NumberByte {
    pub source: WordByte,
    pub weight: u32,
}

/// Stable tag 1 fixes the supported native branch tree: R rejects; SC and TA
/// require their respective inclusive ranges and code[0]; TH accepts any of
/// four inclusive ranges and code[1]; TK requires its range and code[1]; other
/// S/T reject, while every other first prefix byte accepts. Number assembly
/// subtracts decimal_zero from each byte without digit validation and wraps at
/// 32 bits. Code bytes are assembled in the listed most-significant-first order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AuditedPredicate {
    PrefixCodeRangesV1,
}

/// Coordinates are evidence only and never enter predicate identity bytes.
#[derive(Clone, Debug)]
pub(super) struct Evidence {
    pub gate: u32,
    pub predicate: u32,
    pub range_helper: u32,
    pub getter: u32,
    pub source_spans: Vec<(u32, u32)>,
    /// Native getter load order, independent of the assembly order below.
    pub parameter_loads: [u16; 6],
    pub prefix: [WordByte; 2],
    pub code: [WordByte; 4],
    pub number: [NumberByte; 6],
    pub decimal_zero: u8,
    /// R, S, C, T, A, H, K, in the branch-tree order fixed by tag 1.
    pub prefix_tags: [u8; 7],
    pub codes: [[u8; 4]; 2],
    /// SC, TA, four TH ranges, TK, inclusive at both ends.
    pub ranges: [(u32, u32); 7],
    pub semantics: AuditedPredicate,
}

impl Evidence {
    pub(super) fn predicate_value(&self) -> crate::filters::Value {
        use crate::filters::Value as V;
        let byte = |source: WordByte| {
            V::Sequence(vec![
                V::U16(source.parameter),
                V::U8(match source.half {
                    ByteHalf::Low => 0,
                    ByteHalf::High => 1,
                }),
            ])
        };
        let tag = match self.semantics {
            AuditedPredicate::PrefixCodeRangesV1 => 1,
        };
        V::Variant(
            tag,
            vec![
                V::Sequence(self.parameter_loads.iter().copied().map(V::U16).collect()),
                V::Sequence(self.prefix.iter().copied().map(byte).collect()),
                V::Sequence(self.code.iter().copied().map(byte).collect()),
                V::Sequence(
                    self.number
                        .iter()
                        .map(|digit| V::Sequence(vec![byte(digit.source), V::U32(digit.weight)]))
                        .collect(),
                ),
                V::U8(self.decimal_zero),
                V::Bytes(self.prefix_tags.to_vec()),
                V::Sequence(
                    self.codes
                        .iter()
                        .map(|code| V::Bytes(code.to_vec()))
                        .collect(),
                ),
                V::Sequence(
                    self.ranges
                        .iter()
                        .map(|&(first, last)| V::Sequence(vec![V::U32(first), V::U32(last)]))
                        .collect(),
                ),
            ],
        )
    }
}

fn be24(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(3)?)?;
    Some(u32::from_be_bytes([0, b[0], b[1], b[2]]))
}
fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn matches(code: &[u8], shape: &[u8], links: &[(usize, usize)]) -> bool {
    code.len() == shape.len()
        && code.iter().zip(shape).enumerate().all(|(i, (a, b))| {
            a == b
                || links
                    .iter()
                    .any(|&(start, len)| (start..start + len).contains(&i))
        })
}

/// Recognize only stored Normal code. A miss leaves the independently proven
/// FE23 selection intact and provides no unconditional acceptance of FE09.
pub(super) fn discover(normal: &[u8], bound: &crate::startup::BoundSelection) -> Option<Evidence> {
    if bound.requirement.parameter != 0x9f
        || bound.requirement.required != 0xfe23
        || bound.requirement.argument_register != 0
    {
        return None;
    }
    let regions = crate::image::regions(normal)?;
    let at = |address: u32, length: usize| {
        if address & 1 != 0 {
            return None;
        }
        let offset = usize::try_from(address.checked_sub(BASE)?).ok()?;
        let end = offset.checked_add(length)?;
        if !regions.stored.iter().any(|region| {
            let start = region.as_ptr() as usize - normal.as_ptr() as usize;
            start <= offset && end <= start + region.len()
        }) {
            return None;
        }
        normal.get(offset..end)
    };
    let gate_address = bound.requirement.check_address;
    let gate = at(gate_address, GATE.len())?;
    if !matches(gate, GATE, &[(5, 3), (23, 3), (45, 3), (51, 3), (57, 3)])
        || be24(gate, 5)? != bound.requirement.getter_address
    {
        return None;
    }
    // These remain the exact rejection wrappers already required by the
    // positive FE23 selection. The continuation is only a bounded code target.
    for (operand, service) in [(45, 0x14), (51, 0x1a)] {
        if at(be24(gate, operand)?, 6)? != [0x5e, 0x40, 0x0a, service, 0x54, 0x70] {
            return None;
        }
    }
    at(be24(gate, 57)?, 6)?;
    let predicate_address = be24(gate, 23)?;
    let predicate = at(predicate_address, PREDICATE.len())?;
    // The indirect getter's 32-bit address and actual absolute JSR/JMP targets
    // are the only variable bytes. Scalar loads and every branch stay exact.
    let mut predicate_links = vec![(18, 4), (259, 3), (353, 3)];
    predicate_links.extend(RANGE_CALLS.iter().map(|call| (call + 1, 3)));
    if !matches(predicate, PREDICATE, &predicate_links)
        || be32(predicate, 18)? != bound.requirement.getter_address
        || be24(predicate, 259)? != predicate_address.checked_add(492)?
        || be24(predicate, 353)? != predicate_address.checked_add(490)?
    {
        return None;
    }
    let range_address = be24(predicate, RANGE_CALLS[0] + 1)?;
    if at(range_address, RANGE_HELPER.len())? != RANGE_HELPER
        || RANGE_CALLS
            .iter()
            .any(|call| be24(predicate, call + 1) != Some(range_address))
    {
        return None;
    }
    // Re-establish the complete reader graph, including mapped-byte reads and
    // active-record addressing, and bind all local calls to those exact roles.
    let Observation::Known(reader) = crate::image::layout::discover_h8_reader(normal, None) else {
        return None;
    };
    if reader.component != H8ReaderComponent::Normal
        || reader.getter != bound.requirement.getter_address
        || reader.argument_register != 0
        || reader.layout != bound.layout
    {
        return None;
    }
    let role_address = |role| {
        reader
            .functions
            .iter()
            .find(|f| f.role == role)
            .map(|f| f.address)
    };
    let getter = at(reader.getter, GETTER.len())?;
    let resolver_address = be24(getter, 37)?;
    if !matches(getter, GETTER, &[(37, 3), (57, 3), (71, 3)])
        || role_address(H8ReaderRole::Resolver) != Some(resolver_address)
        || role_address(H8ReaderRole::ByteReader) != be24(getter, 57)
        || be24(getter, 57)? != be24(getter, 71)?
    {
        return None;
    }
    let resolver = at(resolver_address, RESOLVER.len())?;
    if !matches(resolver, RESOLVER, &[(51, 3), (201, 3)])
        || be24(resolver, 51)? != resolver_address.checked_add(194)?
        || role_address(H8ReaderRole::Record) != be24(resolver, 201)
    {
        return None;
    }
    let parameter_loads = [
        be16(predicate, 14)?,
        be16(predicate, 34)?,
        be16(predicate, 60)?,
        be16(predicate, 102)?,
        be16(predicate, 156)?,
        be16(predicate, 206)?,
    ];
    let word_byte = |parameter, half| WordByte { parameter, half };
    let [prefix, code_first, code_last, number_first, number_middle, number_last] = parameter_loads;
    let code = [
        word_byte(code_first, ByteHalf::Low),
        word_byte(code_first, ByteHalf::High),
        word_byte(code_last, ByteHalf::Low),
        word_byte(code_last, ByteHalf::High),
    ];
    let number = [
        NumberByte {
            source: word_byte(number_first, ByteHalf::Low),
            weight: be32(predicate, 144)?,
        },
        NumberByte {
            source: word_byte(number_first, ByteHalf::High),
            weight: be32(predicate, 122)?,
        },
        NumberByte {
            source: word_byte(number_middle, ByteHalf::Low),
            weight: be32(predicate, 172)?,
        },
        NumberByte {
            source: word_byte(number_middle, ByteHalf::High),
            weight: u32::from(predicate[197]),
        },
        // Native shifts/adds implement x10 and the final unweighted byte.
        NumberByte {
            source: word_byte(number_last, ByteHalf::Low),
            weight: 10,
        },
        NumberByte {
            source: word_byte(number_last, ByteHalf::High),
            weight: 1,
        },
    ];
    let mut ranges = [(0, 0); 7];
    for (range, offset) in ranges.iter_mut().zip([276, 314, 362, 384, 406, 428, 456]) {
        *range = (be32(predicate, offset + 2)?, be32(predicate, offset + 8)?);
    }
    let mut source_spans = vec![
        (gate_address, gate_address.checked_add(GATE.len() as u32)?),
        (
            predicate_address,
            predicate_address.checked_add(PREDICATE.len() as u32)?,
        ),
        (
            range_address,
            range_address.checked_add(RANGE_HELPER.len() as u32)?,
        ),
    ];
    for function in &reader.functions {
        source_spans.push((
            function.address,
            function
                .address
                .checked_add(u32::try_from(function.bytes).ok()?)?,
        ));
    }
    Some(Evidence {
        gate: gate_address,
        predicate: predicate_address,
        range_helper: range_address,
        getter: reader.getter,
        source_spans,
        parameter_loads,
        prefix: [
            word_byte(prefix, ByteHalf::Low),
            word_byte(prefix, ByteHalf::High),
        ],
        code,
        number,
        decimal_zero: u8::try_from(be16(predicate, 116)?).ok()?,
        prefix_tags: [
            predicate[253],
            predicate[263],
            predicate[269],
            predicate[301],
            predicate[309],
            predicate[357],
            predicate[451],
        ],
        codes: [
            predicate[344..348].try_into().ok()?,
            predicate[484..488].try_into().ok()?,
        ],
        ranges,
        semantics: AuditedPredicate::PrefixCodeRangesV1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put24(bytes: &mut [u8], at: usize, address: u32) {
        bytes[at..at + 3].copy_from_slice(&address.to_be_bytes()[1..]);
    }
    fn fixture(getter: usize, predicate: usize, range: usize) -> Vec<u8> {
        let mut normal = vec![0xff; 0x8000];
        crate::image::layout::install_test_layout_variant(&mut normal, getter, 5);
        let mut gate = GATE.to_vec();
        for (operand, offset) in [
            (5, getter),
            (23, predicate),
            (45, 0x5100),
            (51, 0x5110),
            (57, 0x5120),
        ] {
            put24(&mut gate, operand, BASE + offset as u32);
        }
        normal[0x80..0x80 + gate.len()].copy_from_slice(&gate);
        for (offset, service) in [(0x5100, 0x14), (0x5110, 0x1a)] {
            normal[offset..offset + 6].copy_from_slice(&[0x5e, 0x40, 0x0a, service, 0x54, 0x70]);
        }
        normal[0x5120..0x5126].copy_from_slice(&[0x01, 0, 0x6d, 0xf3, 0x54, 0x70]);
        let mut code = PREDICATE.to_vec();
        code[18..22].copy_from_slice(&(BASE + getter as u32).to_be_bytes());
        put24(&mut code, 259, BASE + predicate as u32 + 492);
        put24(&mut code, 353, BASE + predicate as u32 + 490);
        for call in RANGE_CALLS {
            put24(&mut code, call + 1, BASE + range as u32);
        }
        normal[predicate..predicate + code.len()].copy_from_slice(&code);
        normal[range..range + RANGE_HELPER.len()].copy_from_slice(RANGE_HELPER);
        normal
    }
    fn bound(normal: &[u8]) -> crate::startup::BoundSelection {
        match crate::startup::bound_selection(normal) {
            Observation::Known(bound) => bound,
            other => panic!("unbound test gate: {other:?}"),
        }
    }

    #[test]
    fn native_fields_and_branch_constants_are_retained_without_runtime_values() {
        let normal = fixture(0x1000, 0x4000, 0x5000);
        let value = discover(&normal, &bound(&normal)).expect("full predicate");
        assert_eq!(
            value.parameter_loads,
            [0x190, 0x191, 0x195, 0x192, 0x193, 0x194]
        );
        assert_eq!(value.prefix_tags, *b"RSCTAHK");
        assert_eq!(value.codes, [*b"DLSP", *b"DLCN"]);
        assert_eq!(value.decimal_zero, b'0');
        assert_eq!(
            value.number.map(|byte| byte.weight),
            [100000, 10000, 1000, 100, 10, 1]
        );
        assert_eq!(
            value.number.map(|byte| byte.source.parameter),
            [0x192, 0x192, 0x193, 0x193, 0x194, 0x194]
        );
        assert_eq!(
            value.number.map(|byte| byte.source.half),
            [
                ByteHalf::Low,
                ByteHalf::High,
                ByteHalf::Low,
                ByteHalf::High,
                ByteHalf::Low,
                ByteHalf::High
            ]
        );
        assert_eq!(
            value.ranges,
            [
                (900001, 900012),
                (900025, 900044),
                (2811, 2820),
                (3281, 3290),
                (3311, 3330),
                (3371, 3380),
                (3861, 3900)
            ]
        );
        assert!(value
            .source_spans
            .contains(&(BASE + 0x4000, BASE + 0x4000 + 508)));
        assert!(value
            .source_spans
            .contains(&(BASE + 0x5000, BASE + 0x5000 + 24)));
    }

    #[test]
    fn predicate_scalar_or_instruction_changes_preserve_only_the_primary_selection() {
        let original = fixture(0x1000, 0x4000, 0x5000);
        let mut normal = original.clone();
        // Parameter IDs, byte assembly, zero subtraction, multiplication weight,
        // prefix tag, range bound, code constant, default and return instructions.
        for offset in [15, 41, 117, 147, 253, 279, 345, 489, 507] {
            normal[0x4000 + offset] ^= 1;
            let primary = bound(&normal);
            assert_eq!(primary.requirement.required, 0xfe23);
            assert!(
                discover(&normal, &primary).is_none(),
                "predicate byte {offset}"
            );
            normal.copy_from_slice(&original);
        }
        for offset in [0, 7, 10, 15, 23] {
            normal[0x5000 + offset] ^= 1;
            let primary = bound(&normal);
            assert!(
                discover(&normal, &primary).is_none(),
                "range helper byte {offset}"
            );
            normal.copy_from_slice(&original);
        }
    }

    #[test]
    fn every_helper_link_internal_jump_and_indirect_getter_are_bound() {
        let original = fixture(0x1000, 0x4000, 0x5000);
        let mut normal = original.clone();
        for operand in RANGE_CALLS
            .map(|call| call + 1)
            .into_iter()
            .chain([259, 353])
        {
            normal[0x4000 + operand + 2] ^= 2;
            let primary = bound(&normal);
            assert!(
                discover(&normal, &primary).is_none(),
                "predicate link {operand}"
            );
            normal.copy_from_slice(&original);
        }
        // The getter address is a full 32-bit immediate, not an arbitrary
        // pointer mask. The fixed math service is outside relocation scope.
        for offset in [18, 21, 127, 149, 177, 199] {
            normal[0x4000 + offset] ^= 2;
            assert!(
                discover(&normal, &bound(&normal)).is_none(),
                "call byte {offset}"
            );
            normal.copy_from_slice(&original);
        }
        let primary = bound(&normal);
        let resolver = be24(&normal[0x1000..], 37).unwrap();
        let resolver_offset = (resolver - BASE) as usize;
        for offset in [29, 35, 41, 51, 201] {
            normal[resolver_offset + offset] ^= 2;
            assert!(
                discover(&normal, &primary).is_none(),
                "resolver byte {offset}"
            );
            normal.copy_from_slice(&original);
        }
    }

    #[test]
    fn consistent_code_relocation_changes_coordinates_without_changing_predicate_value() {
        let first = fixture(0x1000, 0x4000, 0x5000);
        let second = fixture(0x2000, 0x4400, 0x5020);
        let first = discover(&first, &bound(&first)).unwrap();
        let second = discover(&second, &bound(&second)).unwrap();
        assert_ne!(first.source_spans, second.source_spans);
        assert_eq!(first.predicate_value(), second.predicate_value());
    }
}
