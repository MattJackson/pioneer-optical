//! Native hardware obligations for a static mechanism on a software target.
//! DSP availability is established from complete local reader/writer bodies;
//! sharing an MMIO address or architecture is insufficient.
use super::native_graph;
use alloc::vec::Vec;
use core::ops::Range;

const BASE: u32 = 0x410000;
const WRITER: u32 = 0x5f680a;
const READER: u32 = 0x5f687a;
const END: u32 = 0x5f6928;
const SHADOW: u32 = 0x33f0;
// Complete native bodies from decoded PR1 Normal SHA-256
// 663dcb14f69d4100473ac5a177a705db7ffdf6e0d2ebe5afd26b264fa832598e.
// Provenance only: no whole-image identity participates in discovery.
const NATIVE: &[u8] = include_bytes!("trajectory_code/software-dsp.bin");

/// Complete target-local DSP port ABI. Reader and writer share the same native
/// word shadow, preserve ER4..ER6 as used, and issue the exact FF90/FF91 protocol.
/// Poll-loop readiness and DSP program availability are separate obligations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dsp {
    /// Writer: R0 address, E0 word value. Arithmetic CCR flags are clobbered.
    pub writer: Range<usize>,
    /// Reader: R0 address, R0 word result. Arithmetic CCR flags are clobbered.
    pub reader: Range<usize>,
    /// Existing target-owned shadow word for register 0x2a0.
    pub shadow: u32,
}
fn stored(normal: &[u8]) -> Option<Vec<Range<usize>>> {
    Some(
        crate::image::regions(normal)?
            .stored
            .iter()
            .map(|b| {
                let start = b.as_ptr() as usize - normal.as_ptr() as usize;
                start..start + b.len()
            })
            .collect(),
    )
}
fn native_match(bytes: &[u8], model: &[u8], mapping: &[(u32, u32, u32)]) -> Option<()> {
    (native_graph::canonical(bytes, mapping)? == model).then_some(())
}
/// Discover a unique complete native DSP service pair, retaining its actual
/// shadow relationship. No donor RAM address or DSP helper is transplanted.
pub fn observe_dsp(normal: &[u8]) -> Option<Dsp> {
    let regions = stored(normal)?;
    let writer_len = (READER - WRITER) as usize;
    let reader_len = (END - READER) as usize;
    let writer_model = NATIVE.get(..writer_len)?;
    let reader_model = NATIVE.get(writer_len..)?;
    let mut found = Vec::new();
    for region in &regions {
        let Some(last) = region.end.checked_sub(writer_len) else {
            continue;
        };
        for at in (region.start + (region.start & 1)..=last).step_by(2) {
            let body = normal.get(at..at + writer_len)?;
            if body.get(..8) != writer_model.get(..8) {
                continue;
            }
            // Exact MOV.W E0-shadow store operand; the complete body is then
            // re-encoded, so these positions alone cannot authorize a match.
            let shadow = u32::from_be_bytes(body.get(102..106)?.try_into().ok()?);
            if shadow & 1 != 0 || shadow.checked_add(2)? > 0x1000000 {
                continue;
            }
            let mapping = [(shadow, shadow + 2, SHADOW)];
            if native_match(body, writer_model, &mapping).is_none() {
                continue;
            }
            for area in &regions {
                let Some(last) = area.end.checked_sub(reader_len) else {
                    continue;
                };
                for reader in (area.start + (area.start & 1)..=last).step_by(2) {
                    let bytes = normal.get(reader..reader + reader_len)?;
                    if bytes.get(..8) != reader_model.get(..8) {
                        continue;
                    }
                    let mapping = [
                        (shadow, shadow + 2, SHADOW),
                        (
                            BASE + at as u32,
                            BASE + at as u32 + writer_len as u32,
                            WRITER,
                        ),
                    ];
                    if native_match(bytes, reader_model, &mapping).is_some() {
                        found.push(Dsp {
                            writer: at..at + writer_len,
                            reader: reader..reader + reader_len,
                            shadow,
                        });
                        if found.len() > 1 {
                            return None;
                        }
                    }
                }
            }
        }
    }
    found.pop()
}

impl Dsp {
    /// Retain the calling convention's entire CCR around the target's native
    /// port writer. The two-byte stack slot is popped on the only return edge;
    /// interrupts and all caller registers retain the native writer contract.
    pub fn writer_adapter(&self) -> Option<Vec<u8>> {
        use h8_asm::{
            isa::{encode_insn, Ea, Insn, Operand as O, Reg, Size},
            Mode, Target,
        };
        let instructions = [
            Insn::new(
                "STC",
                Some(Size::Word),
                [
                    O::Register(Reg::Ccr),
                    O::Address(Ea::PreDecrement(Reg::Long(7))),
                    O::None,
                ],
            ),
            Insn::new(
                "JSR",
                None,
                [
                    O::Address(Ea::Absolute {
                        value: BASE.checked_add(self.writer.start.try_into().ok()?)?,
                        bits: 24,
                    }),
                    O::None,
                    O::None,
                ],
            ),
            Insn::new(
                "LDC",
                Some(Size::Word),
                [
                    O::Address(Ea::PostIncrement(Reg::Long(7))),
                    O::Register(Reg::Ccr),
                    O::None,
                ],
            ),
            Insn::new("RTS", None, [O::None, O::None, O::None]),
        ];
        let mut bytes = Vec::new();
        for insn in instructions {
            bytes.extend(encode_insn(insn, Target::H8S2000, Mode::Advanced).ok()?);
        }
        // Apply the same exact decode/re-encode check as all native graph code.
        native_graph::canonical(&bytes, &[])
    }
}

/// Reservations supplied by the complete mechanism's storage owner. This
/// module never discovers allocations from erased bytes.
#[derive(Clone, Debug)]
pub struct LoaderSlots {
    /// Whole donor loader at its new entry.
    pub code: Range<usize>,
    /// Two complete native 18-row coefficient arrays, in mode order.
    pub tables: [Range<usize>; 2],
    /// Native high-byte word extractor.
    pub extractor: Range<usize>,
    /// CCR-preserving target writer adapter.
    pub writer: Range<usize>,
    /// Two immutable aligned pointer cells, needed only by a pointer donor.
    pub pointers: Option<Range<usize>>,
}
/// Complete loader-stage effects; native mode propagation, controller timing,
/// DSP program state, and allocation ownership remain outer-plan obligations.
#[derive(Clone, Debug)]
pub struct LoaderPlan {
    /// Atomic code, table, and pointer-cell writes.
    pub writes: Vec<(Range<usize>, Vec<u8>)>,
    /// Unchanged target hardware-service witnesses.
    pub protected: Vec<Range<usize>>,
    /// Existing source selection guard, never a persistent write.
    pub required_words: Vec<crate::filters::prerequisites::Word>,
    /// Emitted native loader entry.
    pub entry: u32,
}
/// Lower the complete static donor loader onto actual software-target DSP
/// services. Every code operand is decoded and re-encoded; scalar table bytes,
/// selection predicates, row arithmetic and all register writes remain donor
/// native. Supplied slots must already be positively owned by the outer plan.
pub fn plan_loader(target: &[u8], donor: &[u8], slots: LoaderSlots) -> Option<LoaderPlan> {
    use crate::filters::phase::bundle::waveforms::loader::{self, Table};
    let dsp = observe_dsp(target)?;
    let source = loader::observe(donor).ok()?;
    if source.computed {
        return None;
    }
    loader::readback::observe(donor, source.readback, source.writer).ok()?;
    let graph = super::observe(donor).ok()?;
    let table_roles = source.tables?;
    let pointer = matches!(table_roles, [Table::Pointer(_), Table::Pointer(_)]);
    if !pointer && !matches!(table_roles, [Table::Literal(_), Table::Literal(_)]) {
        return None;
    }
    if pointer != slots.pointers.is_some() || pointer != graph.erased_parameter.is_some() {
        return None;
    }
    let program = loader::logical_program(donor).ok()?;
    let adapter = dsp.writer_adapter()?;
    if slots.code.len() != program.len()
        || slots.writer.len() != adapter.len()
        || slots.extractor.len() != 4
        || slots.tables.iter().any(|r| r.len() != 72)
        || slots
            .pointers
            .as_ref()
            .is_some_and(|r| r.len() != 8 || r.start & 3 != 0)
    {
        return None;
    }
    let ranges: Vec<_> = core::iter::once(&slots.code)
        .chain(&slots.tables)
        .chain([&slots.extractor, &slots.writer])
        .chain(&slots.pointers)
        .collect();
    let stored = stored(target)?;
    for (i, r) in ranges.iter().enumerate() {
        if r.start & 1 != 0
            || !stored.iter().any(|s| s.start <= r.start && r.end <= s.end)
            || ranges[..i]
                .iter()
                .any(|s| s.start < r.end && r.start < s.end)
            || [&dsp.writer, &dsp.reader]
                .iter()
                .any(|s| s.start < r.end && r.start < s.end)
        {
            return None;
        }
    }
    let address = |r: &Range<usize>| BASE.checked_add(u32::try_from(r.start).ok()?);
    let writer = address(&slots.writer)?;
    let extractor = address(&slots.extractor)?;
    let mut mapping = alloc::vec![
        (source.writer, source.writer.checked_add(1)?, writer),
        (
            source.readback,
            source.readback.checked_add(1)?,
            address(&dsp.reader)?
        ),
        (
            source.coefficient_getter,
            source.coefficient_getter.checked_add(1)?,
            extractor
        ),
    ];
    let mut writes = Vec::new();
    let mut cells = Vec::new();
    for (i, (role, to)) in table_roles.into_iter().zip(&slots.tables).enumerate() {
        let source_address = match role {
            Table::Literal(a) | Table::Pointer(a) => a,
        };
        let value = address(to)?;
        let destination = if let Some(p) = &slots.pointers {
            cells.extend(value.to_be_bytes());
            address(p)?.checked_add(i as u32 * 4)?
        } else {
            value
        };
        mapping.push((source_address, source_address.checked_add(1)?, destination));
        writes.push((
            to.clone(),
            donor.get(graph.selected.coefficients[i].clone())?.to_vec(),
        ));
    }
    let emitted = native_graph::canonical(&program, &mapping)?;
    let entry = address(&slots.code)?;
    let expected_tables = if let Some(p) = &slots.pointers {
        writes.push((p.clone(), cells));
        [
            Table::Pointer(address(p)?),
            Table::Pointer(address(p)?.checked_add(4)?),
        ]
    } else {
        [
            Table::Literal(address(&slots.tables[0])?),
            Table::Literal(address(&slots.tables[1])?),
        ]
    };
    writes.extend([
        (slots.code, emitted),
        (slots.extractor, alloc::vec![0x0c, 0x08, 0x54, 0x70]),
        (slots.writer, adapter),
    ]);
    let mut changed = target.to_vec();
    for (r, b) in &writes {
        if r.len() != b.len() {
            return None;
        }
        changed.get_mut(r.clone())?.copy_from_slice(b);
    }
    let observed = loader::observe(&changed).ok()?;
    if observed.program.start as u32 + BASE != entry
        || observed.loader != source.loader
        || observed.tables != Some(expected_tables)
        || observed.writer != writer
        || observed.coefficient_getter != extractor
        || observed.readback != address(&dsp.reader)?
    {
        return None;
    }
    Some(LoaderPlan {
        writes,
        protected: alloc::vec![dsp.writer, dsp.reader],
        required_words: if pointer {
            alloc::vec![crate::filters::prerequisites::Word {
                parameter: 0x28f,
                value: 1
            }]
        } else {
            Vec::new()
        },
        entry,
    })
}

/// Actual software-target sequencer command transport, including timeout
/// diagnostics, native error-state setter, and the complete busy-bit observer.
#[derive(Clone, Debug)]
pub struct Command {
    /// Native command entry: R0 word; success byte in R0L.
    pub entry: u32,
    /// Native FF94 bit-one query, returning zero/one in R0L.
    pub busy: u32,
    /// Complete unchanged code, string and service witnesses.
    pub protected: Vec<Range<usize>>,
}
const COMMAND_RANGES: &[(u32, u32)] = &[
    (0x5f66bc, 0x5f6752),
    (0x5f6752, 0x5f6760),
    (0x5f0102, 0x5f0164),
    (0x5f6802, 0x5f680a),
    (0x661a06, 0x661a39),
];
const COMMAND_NATIVE: &[u8] = include_bytes!("trajectory_code/software-command.bin");
fn command_model() -> Option<native_graph::Graph> {
    let mut reference = alloc::vec![255;(COMMAND_RANGES.last()?.1-BASE) as usize];
    let mut cursor = 0;
    let mut ranges = Vec::new();
    for &(a, z) in COMMAND_RANGES {
        let r = (a - BASE) as usize..(z - BASE) as usize;
        reference
            .get_mut(r.clone())?
            .copy_from_slice(COMMAND_NATIVE.get(cursor..cursor + r.len())?);
        cursor += r.len();
        ranges.push(r);
    }
    if cursor != COMMAND_NATIVE.len() {
        return None;
    }
    native_graph::Graph::new(&reference, BASE, &ranges[..4], &ranges[4..])
}
/// Bind command transport independently of a phase controller. No claim that
/// the target DSP implements a donor command follows from this transport proof.
/// Target shadow/error RAM operands remain exact native external obligations.
pub fn observe_command(normal: &[u8]) -> Option<Command> {
    let model = command_model()?;
    let locations = model.discover(normal, BASE, &stored(normal)?);
    let [bound] = locations.as_slice() else {
        return None;
    };
    Some(Command {
        entry: BASE.checked_add(bound.ranges.first()?.start.try_into().ok()?)?,
        busy: BASE.checked_add(bound.ranges.get(1)?.start.try_into().ok()?)?,
        protected: bound.ranges.clone(),
    })
}

/// Complete native DSP setup stage before the movement command. Its paired
/// loader's actual mode-to-direction coherence is proved in the immutable donor.
#[derive(Clone, Debug)]
pub struct ControlPlan {
    /// Whole source control routine, with only proven DSP service operands moved.
    pub code: (Range<usize>, Vec<u8>),
    /// Retained target port and donor control witnesses.
    pub target_services: Dsp,
    /// The source controller's positively bound mode-coherence graph.
    pub source: super::dsp_control_bridge::Binding,
}
/// Lower native DSP mode setup with no guessed register defaults. Register
/// F930's source branch, every 0x554 bit update, source 0xf6a..0xf70-to-0x4b7
/// transfer, and final 0x407 write remain the complete OEM program. The outer
/// controller must execute this after the same-mode loader and before movement.
pub fn plan_control(
    target: &[u8],
    donor: &[u8],
    donor_kernel: &[u8],
    code: Range<usize>,
    writer_adapter: Range<usize>,
) -> Option<ControlPlan> {
    let target_services = observe_dsp(target)?;
    let source = super::dsp_control_bridge::observe(donor, donor_kernel).ok()?;
    let loader = crate::filters::phase::bundle::waveforms::loader::observe(donor).ok()?;
    let adapter = target_services.writer_adapter()?;
    if code.len() != source.control.len()
        || writer_adapter.len() != adapter.len()
        || code.start & 1 != 0
        || writer_adapter.start & 1 != 0
        || code.start < writer_adapter.end && writer_adapter.start < code.end
    {
        return None;
    }
    let stored = stored(target)?;
    if [&code, &writer_adapter].iter().any(|r| {
        !stored.iter().any(|s| s.start <= r.start && r.end <= s.end)
            || [&target_services.writer, &target_services.reader]
                .iter()
                .any(|s| s.start < r.end && r.start < s.end)
    }) {
        return None;
    }
    let mapping = [
        (
            loader.writer,
            loader.writer.checked_add(1)?,
            BASE.checked_add(writer_adapter.start.try_into().ok()?)?,
        ),
        (
            loader.readback,
            loader.readback.checked_add(1)?,
            BASE.checked_add(target_services.reader.start.try_into().ok()?)?,
        ),
    ];
    let body = native_graph::canonical(donor.get(source.control.clone())?, &mapping)?;
    Some(ControlPlan {
        code: (code, body),
        target_services,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn software_dsp_services_bind_only_complete_coherent_native_pair() {
        let mut normal = alloc::vec![255; 0x200000];
        let writer = 0x1000;
        let reader = 0x2000;
        let shadow = 0x4488;
        let split = (READER - WRITER) as usize;
        let mapping = [
            (WRITER, READER, BASE + writer as u32),
            (SHADOW, SHADOW + 2, shadow),
        ];
        let w = native_graph::canonical(&NATIVE[..split], &mapping).unwrap();
        let r = native_graph::canonical(&NATIVE[split..], &mapping).unwrap();
        normal[writer..writer + w.len()].copy_from_slice(&w);
        normal[reader..reader + r.len()].copy_from_slice(&r);
        let bound = observe_dsp(&normal).unwrap();
        assert_eq!(bound.writer, writer..writer + w.len());
        assert_eq!(bound.reader, reader..reader + r.len());
        assert_eq!(bound.shadow, shadow);
        assert!(bound.writer_adapter().is_some());
        normal[reader + 64] ^= 1;
        assert!(observe_dsp(&normal).is_none());
    }
}
