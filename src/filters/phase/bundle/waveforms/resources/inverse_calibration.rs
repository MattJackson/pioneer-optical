//! Static DSP-coordinate arithmetic on a software target. The values 0x127 and
//! 0x128 here are DSP registers, not persistent calibration words. Complete
//! controller, DSP-program, allocation and teardown proofs remain obligations
//! of the composing owner.
use super::{dispatch_bridge, inverse_controller, native_graph, software, trajectory_bridge};
use crate::filters::phase::bundle::{conversions, Element};
use alloc::vec::Vec;
use core::ops::Range;

const BASE: u32 = 0x410000;
const ROW: &[u8] = &[0x6e, 8, 0, 4, 0x54, 0x70];
// Complete PR1 native movement constructor and context getter. Operand fields
// below are bound to the observed producer, stored vtable, and common RAM.
const CTOR: &[u8] = &[
    1, 0, 0x6d, 0xf3, 0x0f, 0x83, 0x46, 0x0c, 0x1a, 0x80, 0xf8, 0x0c, 0x5e, 0x62, 0x3e, 0x5c, 0x0f,
    0x83, 0x47, 0x2e, 0x7a, 1, 0, 0x69, 0x34, 0x52, 1, 0, 0x69, 0xb1, 0x5e, 0x5d, 0x6f, 0x44, 0x18,
    0, 0x6e, 0xb0, 0, 4, 0x6e, 0xb0, 0, 5, 0xf9, 8, 0x6e, 0xb9, 0, 6, 0x6e, 0xb0, 0, 0x0a, 0x79, 1,
    0, 0xc8, 0x6f, 0xb1, 0, 8, 0x6e, 0xb0, 0, 0x0b, 0x0f, 0xb0, 1, 0, 0x6d, 0x73, 0x54, 0x70,
];
const CONTEXT: &[u8] = &[
    1, 0, 0x6d, 0xf3, 0x7a, 3, 0, 0, 0x1e, 0x68, 0x6b, 0x20, 0, 0, 0x1e, 0x66, 0x46, 0x0e, 0x79, 1,
    0, 1, 0x6b, 0xa1, 0, 0, 0x1e, 0x66, 0x0f, 0xb0, 0x55, 0x68, 0x0f, 0xb0, 1, 0, 0x6d, 0x73, 0x54,
    0x70,
];
const SETTER: &[u8] = &[
    1, 0, 0x6d, 0xf3, 0x0f, 0x83, 0xf8, 1, 0x0c, 0x90, 0x5e, 0, 0, 0, 0x6e, 0xb8, 0, 4, 1, 0, 0x6d,
    0x73, 0x54, 0x70,
];
fn word(b: &[u8], at: usize, width: usize) -> Option<u32> {
    Some(
        b.get(at..at.checked_add(width)?)?
            .iter()
            .fold(0, |a, b| a << 8 | u32::from(*b)),
    )
}
fn matches(b: &[u8], model: &[u8], holes: &[Range<usize>]) -> bool {
    b.len() == model.len()
        && b.iter()
            .zip(model)
            .enumerate()
            .all(|(i, (a, b))| holes.iter().any(|r| r.contains(&i)) || a == b)
        && native_graph::canonical(b, &[]).is_some()
}
fn stored(normal: &[u8], range: &Range<usize>) -> bool {
    !range.is_empty()
        && crate::image::regions(normal).is_some_and(|regions| {
            regions.stored.iter().any(|b| {
                let at = b.as_ptr() as usize - normal.as_ptr() as usize;
                at <= range.start && range.end <= at + b.len()
            })
        })
}
fn span(normal: &[u8], address: u32, size: usize) -> Option<Range<usize>> {
    let at = address.checked_sub(BASE)? as usize;
    let r = at..at.checked_add(size)?;
    stored(normal, &r).then_some(r)
}
/// Target-owned movement object services. The context constructor initializes
/// the exact generated phase producer; the setter reaches the bound dispatcher
/// and saves its returned row in object[4]. No donor RAM coordinate is copied.
#[derive(Clone, Debug)]
pub struct Movement {
    /// Existing initialized movement object getter.
    pub context: u32,
    /// Existing R1L row setter, with ER0 object and native dispatch side effects.
    pub setter: u32,
    /// Native code/data that must remain unchanged by the composing owner.
    pub protected: Vec<Range<usize>>,
}
/// Bind the full native context/constructor and dispatch-linked row setter.
pub fn observe_movement(normal: &[u8]) -> Option<Movement> {
    let dispatch = dispatch_bridge::observe(normal).ok()?;
    if dispatch.kind != dispatch_bridge::Kind::Software {
        return None;
    }
    let producer = software::observe_producer(normal).ok()?;
    let mut setter = None;
    for call in &dispatch.callers[0] {
        let start = call.start.checked_sub(10)?;
        let r = start..start.checked_add(SETTER.len())?;
        if !stored(normal, &r)
            || !matches(
                normal.get(r.clone())?,
                SETTER,
                core::slice::from_ref(&(11..14)),
            )
        {
            continue;
        }
        if setter.replace(r).is_some() {
            return None;
        }
    }
    let setter = setter?;
    let regions = crate::image::regions(normal)?;
    let mut contexts = Vec::new();
    for region in regions.stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        for (offset, body) in region.windows(CONTEXT.len()).enumerate() {
            let at = start + offset;
            if at & 1 != 0 || !matches(body, CONTEXT, &[6..10, 12..16, 24..28, 31..32]) {
                continue;
            }
            let object = word(body, 6, 4)?;
            let flag = word(body, 12, 4)?;
            if object == 0
                || object & 1 != 0
                || object.checked_sub(2)? != flag
                || word(body, 24, 4)? != flag
            {
                continue;
            }
            let ctor =
                (BASE as usize + at + 32).checked_add_signed(body[31] as i8 as isize)? as u32;
            let Some(ctor_range) = span(normal, ctor, CTOR.len()) else {
                continue;
            };
            let code = normal.get(ctor_range.clone())?;
            if !matches(code, CTOR, &[13..16, 22..26, 31..34])
                || word(code, 31, 3)? != BASE + producer.initializer.start as u32
            {
                continue;
            }
            let Some(vtable) = span(normal, word(code, 22, 4)?, 20) else {
                continue;
            };
            contexts.push(Movement {
                context: BASE + at as u32,
                setter: BASE + setter.start as u32,
                protected: alloc::vec![
                    at..at + CONTEXT.len(),
                    ctor_range,
                    vtable,
                    setter.clone(),
                    producer.initializer.clone()
                ],
            });
        }
    }
    if contexts.len() != 1 {
        return None;
    }
    contexts.pop()
}
/// Storage supplied by the complete mechanism's positive retirement proof.
#[derive(Clone, Debug)]
pub struct Slots {
    /// Base, offset, and step programs in that order, exact native lengths.
    pub programs: [Range<usize>; 3],
    /// Six-byte native object[4] getter.
    pub row: Range<usize>,
    /// Complete CCR-preserving adapter to the existing target DSP writer.
    pub writer: Range<usize>,
}
/// Native program changes; allocation and full-controller proofs are separate.
#[derive(Clone, Debug)]
pub struct Plan {
    /// Native arithmetic variants, in base/offset/step order.
    pub variants: [u8; 3],
    /// Exact atomic Normal writes.
    pub writes: Vec<(Range<usize>, Vec<u8>)>,
    /// Source entry to target entry mappings for the controller composition.
    pub entries: Vec<(u32, u32)>,
    /// Target native witnesses that must remain unchanged.
    pub protected: Vec<Range<usize>>,
}
/// Transfer the complete static conversion programs, retaining the target's
/// logical movement object and public position counter. No persistent reads or
/// writes are added. Exact resident ownership belongs to the outer mechanism.
pub fn plan(target: &[u8], donor: &[u8], slots: Slots) -> Option<Plan> {
    let source_roles = trajectory_bridge::TargetRoles::discover(donor)?;
    let target_roles = trajectory_bridge::SoftwareRoles::discover(target)?;
    let movement = observe_movement(target)?;
    let dsp = inverse_controller::observe_dsp(target)?;
    let source_loader = super::loader::observe(donor).ok()?;
    super::loader::readback::observe(donor, source_loader.readback, source_loader.writer).ok()?;
    let programs = conversions::bind_native(donor).ok()?;
    if programs.len() != 3
        || programs.iter().map(|p| p.element).collect::<Vec<_>>()
            != [
                Element::CalibrationBase,
                Element::CalibrationOffset,
                Element::CalibrationStep,
            ]
    {
        return None;
    }
    let source = |a| source_roles.address(a);
    let getter = source(0x538b74)?;
    if donor.get(span(donor, getter, ROW.len())?)? != ROW {
        return None;
    }
    let adapter = dsp.writer_adapter()?;
    if slots.row.len() != ROW.len() || slots.writer.len() != adapter.len() {
        return None;
    }
    let address = |r: &Range<usize>| BASE.checked_add(u32::try_from(r.start).ok()?);
    let mapping = [
        (source_loader.readback, dsp.reader.start as u32 + BASE),
        (source_loader.writer, address(&slots.writer)?),
        (source(0x538c7a)?, movement.context),
        (getter, address(&slots.row)?),
        (source(0x538b0c)?, movement.setter),
        (source(0x531a86)?, target_roles.address(0x5d003e)?),
    ];
    let mut protected = movement.protected;
    protected.extend([dsp.reader.clone(), dsp.writer.clone()]);
    protected.push(target_roles.span((0x5d003e - BASE) as usize..(0x5d0046 - BASE) as usize)?);
    let ranges: Vec<_> = slots
        .programs
        .iter()
        .chain([&slots.row, &slots.writer])
        .collect();
    for (i, r) in ranges.iter().enumerate() {
        if r.start & 1 != 0
            || !stored(target, r)
            || ranges[..i]
                .iter()
                .any(|s| s.start < r.end && r.start < s.end)
            || protected.iter().any(|s| s.start < r.end && r.start < s.end)
        {
            return None;
        }
    }
    let mut writes = alloc::vec![
        (slots.row.clone(), ROW.to_vec()),
        (slots.writer.clone(), adapter)
    ];
    let mut entries = Vec::new();
    for (p, r) in programs.iter().zip(&slots.programs) {
        if p.body.bytes.len() != r.len() {
            return None;
        }
        // Every source call must name a positively bound semantic service.
        if p.calls
            .iter()
            .any(|c| !mapping.iter().any(|(a, _)| *a == c.target))
        {
            return None;
        }
        let relocation: Vec<_> = mapping
            .iter()
            .map(|&(a, b)| Some((a, a.checked_add(1)?, b)))
            .collect::<Option<_>>()?;
        let bytes = native_graph::relocate(&p.body.bytes, p.entry, address(r)?, &relocation)?;
        for call in &p.calls {
            let wanted = mapping.iter().find(|(a, _)| *a == call.target)?.1;
            if bytes.get(call.offset) != Some(&0x5e) || word(&bytes, call.offset + 1, 3)? != wanted
            {
                return None;
            }
        }
        writes.push((r.clone(), bytes));
        entries.push((p.entry, address(r)?));
    }
    Some(Plan {
        variants: [
            programs[0].variant,
            programs[1].variant,
            programs[2].variant,
        ],
        writes,
        entries,
        protected,
    })
}
