//! Complete native H8 DSP waveform-loader binding and OEM transplantation.
use crate::filters::phase::bundle::{sites, Loader, Template};
use alloc::vec::Vec;
use core::ops::Range;
/// Complete computed-to-plain native coefficient transfer.
pub mod coefficient_bridge;
/// Complete computed/scaled DSP graph and native direction transformation.
pub mod computed;
/// Complete DSP read-helper ABI proof.
pub mod readback;
mod shapes;
/// Complete DSP write-helper ABI proof.
pub mod writer;

#[derive(Clone, Copy)]
enum FieldKind {
    Call,
    Literal,
    Ram,
    Data,
    Constant,
}
#[derive(Clone, Copy)]
struct Field {
    at: usize,
    width: usize,
    kind: FieldKind,
}
#[derive(Clone, Copy)]
struct Shape {
    loader: Loader,
    computed: bool,
    bytes: Template,
    fields: &'static [Field],
    coefficient: [usize; 2],
    writer: usize,
    readback: usize,
    tables: &'static [usize],
}
/// How the native routine obtains one coefficient-table address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    /// Image-resident table at its native CPU address.
    Literal(u32),
    /// Pointer loaded from a memory slot; RAM initialization or image-cell contents must be bound separately.
    Pointer(u32),
}
/// Complete native loader and its local resource relationships.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// First stored program span in decoded Normal.
    pub program: Range<usize>,
    /// Physical instruction spans, including a single overflow fragment when split.
    pub spans: Vec<Range<usize>>,
    /// Native fetch/address convention.
    pub loader: Loader,
    /// Table for zero and nonzero mode arguments, respectively.
    pub tables: Option<[Table; 2]>,
    /// True when the routine computes/scales coefficients before their extraction.
    pub computed: bool,
    /// Native word-to-byte extractor used for both coefficients.
    pub coefficient_getter: u32,
    /// Native DSP register writer.
    pub writer: u32,
    /// Native DSP register reader.
    pub readback: u32,
}
/// A complete loader proof or rewrite is unavailable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// No unique complete loader was recognized.
    Unresolved,
    /// A bound resource relationship disagreed.
    ResourceMismatch,
    /// The computed program cannot represent the requested per-mode table selection.
    ComputedUnsupported,
    /// A growing program needs explicit caller-owned code space.
    SpaceRequired,
    /// Caller code/table space is invalid or occupied.
    InvalidSpace,
    /// Rewritten native facts did not agree with the requested program.
    VerificationFailed,
}
fn value(normal: &[u8], start: usize, shape: &Shape, at: usize) -> Result<u32, Error> {
    let field = shape
        .fields
        .iter()
        .find(|f| f.at == at)
        .ok_or(Error::ResourceMismatch)?;
    let bytes = normal
        .get(start + at..start + at + field.width)
        .ok_or(Error::ResourceMismatch)?;
    Ok(bytes.iter().fold(0, |v, b| (v << 8) | u32::from(*b)))
}
fn bind(normal: &[u8]) -> Result<(Binding, &'static Shape, Vec<u8>), Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut found = None;
    for shape in shapes::SHAPES {
        for at in sites(normal, &regions.stored, &shape.bytes[..12]) {
            let Some(body) = crate::filters::phase::native::placement::read(
                normal,
                &regions.stored,
                at,
                shape.bytes,
            ) else {
                continue;
            };
            if found.is_some() {
                return Err(Error::Unresolved);
            }
            let get = |offset| value(&body.bytes, 0, shape, offset);
            let coefficient = get(shape.coefficient[0])?;
            if coefficient != get(shape.coefficient[1])? {
                return Err(Error::ResourceMismatch);
            }
            let leaf = coefficient
                .checked_sub(0x410000)
                .ok_or(Error::ResourceMismatch)? as usize;
            if normal.get(leaf..leaf + 4) != Some(&[0x0c, 0x08, 0x54, 0x70][..])
                || !regions.stored.iter().any(|region| {
                    let start = region.as_ptr() as usize - normal.as_ptr() as usize;
                    leaf >= start && leaf + 4 <= start + region.len()
                })
            {
                return Err(Error::ResourceMismatch);
            }
            if shape.computed {
                // Both channels share the table, mode inputs and arithmetic
                // helpers; address-range checks alone do not prove this graph.
                let calls: Vec<_> = shape
                    .fields
                    .iter()
                    .filter(|f| matches!(f.kind, FieldKind::Call))
                    .map(|f| get(f.at))
                    .collect::<Result<_, _>>()?;
                let data: Vec<_> = shape
                    .fields
                    .iter()
                    .filter(|f| matches!(f.kind, FieldKind::Data))
                    .map(|f| get(f.at))
                    .collect::<Result<_, _>>()?;
                if calls.len() != 14
                    || data.is_empty()
                    || calls[0] != calls[1]
                    || data.iter().any(|address| *address != data[0])
                    || calls[2] != calls[3]
                    || calls[2] != calls[7]
                    || [5, 8, 9].into_iter().any(|i| calls[i] != calls[4])
                {
                    return Err(Error::ResourceMismatch);
                }
            }
            let writer = get(shape.writer)?;
            let readback = get(shape.readback)?;
            // Both address-selected and direct-call writers have the same ABI.
            // Bind every fixed call at the writer's repeated selection sites.
            for field in shape.fields {
                let address = get(field.at)?;
                if matches!(field.kind, FieldKind::Constant) {
                    computed::validate_fold(normal, get(13)?, address as u16)?;
                    continue;
                }
                if address & 1 != 0 {
                    return Err(Error::ResourceMismatch);
                }
                match field.kind {
                    FieldKind::Call
                        if address < 0x100000 || address >= 0x410000 + normal.len() as u32 =>
                    {
                        return Err(Error::ResourceMismatch)
                    }
                    FieldKind::Literal | FieldKind::Data
                        if address < 0x410000 || address >= 0x410000 + normal.len() as u32 =>
                    {
                        return Err(Error::ResourceMismatch)
                    }
                    _ => {}
                }
                if matches!(field.kind, FieldKind::Call)
                    && field.at >= 3
                    && body.bytes.get(field.at - 3..field.at - 1) == Some(&[0x0d, 0x38][..])
                    && address != writer
                {
                    return Err(Error::ResourceMismatch);
                }
            }
            let mut table_reads = Vec::new();
            for offset in shape.tables {
                let field = shape
                    .fields
                    .iter()
                    .find(|f| f.at == *offset)
                    .ok_or(Error::ResourceMismatch)?;
                table_reads.push(match field.kind {
                    FieldKind::Literal | FieldKind::Data => Table::Literal(get(*offset)?),
                    FieldKind::Ram => Table::Pointer(get(*offset)?),
                    _ => return Err(Error::ResourceMismatch),
                });
            }
            let tables = match table_reads.as_slice() {
                [] => None,
                [one] => Some([*one, *one]),
                [Table::Pointer(a), Table::Pointer(b)] => {
                    Some([Table::Pointer(*a), Table::Pointer(*b)])
                }
                [nonzero, zero] => Some([*zero, *nonzero]),
                _ => return Err(Error::ResourceMismatch),
            };
            found = Some((
                Binding {
                    program: body.spans[0].clone(),
                    spans: body.spans,
                    loader: shape.loader,
                    tables,
                    computed: shape.computed,
                    coefficient_getter: coefficient,
                    writer,
                    readback,
                },
                shape,
                body.bytes,
            ));
        }
    }
    found.ok_or(Error::Unresolved)
}
/// Bind the entire loader program, never only its address-selection snippet.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    Ok(bind(normal)?.0)
}

/// Recover the complete matched OEM instruction stream, excluding a placement
/// jump and padding. Relative branches retain their original logical offsets.
pub fn logical_program(normal: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(bind(normal)?.2)
}

/// Transplant a recognized noncomputed OEM loader without changing its fetch
/// algorithm. Only declared helper/table address operands are relocated. Pointer
/// slots retain pointer semantics; their initialization and live prerequisites
/// belong to the caller. Growth retains the original prefix and uses h8-asm
/// to jump to a caller-owned suffix; no relative branch may cross that split.
/// Table bytes and image integrity are not changed here.
pub fn transplant_plain(
    normal: &[u8],
    donor: &[u8],
    tables: [Table; 2],
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let (before, _, original_code) = bind(normal)?;
    let (source, shape, mut code) = bind(donor)?;
    if before.computed || source.computed {
        return Err(Error::ComputedUnsupported);
    }
    readback::observe(normal, before.readback, before.writer)?;
    readback::observe(donor, source.readback, source.writer)?;
    let source_tables = source.tables.ok_or(Error::ResourceMismatch)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let contains = |span: &Range<usize>| {
        regions.stored.iter().any(|r| {
            let at = r.as_ptr() as usize - normal.as_ptr() as usize;
            span.start >= at && span.end <= at + r.len()
        })
    };
    for (old, new) in source_tables.into_iter().zip(tables) {
        match (old, new) {
            (Table::Literal(_), Table::Literal(address)) => {
                let at = address.checked_sub(0x410000).ok_or(Error::InvalidSpace)? as usize;
                if address & 1 != 0 || !contains(&(at..at + 72)) {
                    return Err(Error::InvalidSpace);
                }
            }
            (Table::Pointer(_), Table::Pointer(address)) if address != 0 && address & 3 == 0 => {}
            _ => return Err(Error::ResourceMismatch),
        }
    }
    if source_tables[0] == source_tables[1] && tables[0] != tables[1] {
        return Err(Error::ResourceMismatch);
    }
    for field in shape.fields {
        let address = if shape.tables.contains(&field.at) {
            let old = value(&code, 0, shape, field.at)?;
            let role = source_tables
                .iter()
                .position(|table| match table {
                    Table::Literal(address) | Table::Pointer(address) => *address == old,
                })
                .ok_or(Error::ResourceMismatch)?;
            match tables[role] {
                Table::Literal(address) | Table::Pointer(address) => address,
            }
        } else if shape.coefficient.contains(&field.at) {
            before.coefficient_getter
        } else if field.at == shape.readback {
            before.readback
        } else if value(&code, 0, shape, field.at)? == source.writer {
            before.writer
        } else {
            return Err(Error::ResourceMismatch);
        };
        crate::filters::phase::native::encoding::retarget_field(
            &mut code,
            field.at,
            field.width,
            address,
        )
        .ok_or(Error::ResourceMismatch)?;
    }
    for table in tables {
        let (address, size) = match table {
            Table::Literal(address) => (address, 72),
            Table::Pointer(address) => (address, 4),
        };
        if let Some(at) = address.checked_sub(0x410000).map(|a| a as usize) {
            if before
                .spans
                .iter()
                .any(|span| span.start < at + size && at < span.end)
            {
                return Err(Error::InvalidSpace);
            }
        }
    }
    if code == original_code {
        return Ok(normal.to_vec());
    }
    let prior_spill = before.spans.get(1);
    let mut changed = normal.to_vec();
    if code.len() <= before.program.len() {
        crate::filters::phase::native::encoding::nops(&mut changed[before.program.clone()])
            .ok_or(Error::InvalidSpace)?;
        changed[before.program.start..before.program.start + code.len()].copy_from_slice(&code);
        if let Some(span) = prior_spill {
            crate::filters::phase::native::encoding::nops(&mut changed[span.clone()])
                .ok_or(Error::InvalidSpace)?;
        }
    } else {
        let space = reservation
            .or_else(|| prior_spill.cloned())
            .ok_or(Error::SpaceRequired)?;
        let reusing = prior_spill == Some(&space);
        if space.start & 1 != 0
            || space.end & 1 != 0
            || space.start > space.end
            || !contains(&space)
            || before.spans.iter().any(|span| {
                space.start < span.end
                    && span.start < space.end
                    && !(reusing && Some(span) == prior_spill)
            })
            || (!reusing
                && !normal
                    .get(space.clone())
                    .is_some_and(|bytes| bytes.iter().all(|b| *b == 0xff)))
        {
            return Err(Error::InvalidSpace);
        }
        for table in tables {
            let (address, size) = match table {
                Table::Literal(address) => (address, 72),
                Table::Pointer(address) => (address, 4),
            };
            if let Some(at) = address.checked_sub(0x410000).map(|a| a as usize) {
                if space.start < at + size && at < space.end {
                    return Err(Error::InvalidSpace);
                }
            }
        }
        let address = 0x410000usize
            .checked_add(space.start)
            .filter(|a| *a <= 0xffffff)
            .ok_or(Error::InvalidSpace)? as u32;
        let (prefix, spill) = crate::filters::phase::native::placement::split_closed(
            &code,
            (0x410000 + before.program.start) as u32,
            before.program.len(),
            address,
        )
        .ok_or(Error::InvalidSpace)?;
        if spill.len() > space.len() {
            return Err(Error::InvalidSpace);
        }
        changed[before.program.clone()].copy_from_slice(&prefix);
        crate::filters::phase::native::encoding::nops(&mut changed[space.clone()])
            .ok_or(Error::InvalidSpace)?;
        changed[space.start..space.start + spill.len()].copy_from_slice(&spill);
        if let Some(span) = prior_spill.filter(|_| !reusing) {
            crate::filters::phase::native::encoding::nops(&mut changed[span.clone()])
                .ok_or(Error::InvalidSpace)?;
        }
    }
    let after = observe(&changed)?;
    if after.computed
        || after.loader != source.loader
        || after.tables != Some(tables)
        || after.coefficient_getter != before.coefficient_getter
        || after.writer != before.writer
        || after.readback != before.readback
    {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

/// Specialize the target's complete plain loader to a donor's ascending DSP
/// addresses. The donor's wrapped even coefficients must be normalized by the
/// caller. All helper calls, loop bounds, clipping and readback remain target
/// OEM instructions; only the two address computations change in place.
/// No pointer cell or executable reservation is needed.
pub fn specialize_ascending(normal: &[u8], donor: &[u8]) -> Result<Vec<u8>, Error> {
    use crate::filters::phase::{bundle, native::encoding};
    use h8_asm::{
        isa::{decode_insn, encode_insn, Operand},
        Mode, Target,
    };
    let (before, _, code) = bind(normal)?;
    let (source, _, source_code) = bind(donor)?;
    if before.computed
        || source.computed
        || before.spans.len() != 1
        || !matches!(before.loader, Loader::Descending | Loader::Ascending)
        || source.loader != Loader::AscendingNegated17
        || !matches!(before.tables, Some([Table::Literal(_), Table::Literal(_)]))
    {
        return Err(Error::ResourceMismatch);
    }
    readback::observe(normal, before.readback, before.writer)?;
    readback::observe(donor, source.readback, source.writer)?;
    if before.loader == Loader::Ascending {
        return Ok(normal.to_vec());
    }
    let destination = sites(&code, &[&code], bundle::LOADER_DESCENDING);
    let origins = sites(&source_code, &[&source_code], bundle::LOADER_ASCENDING);
    let ([at], [from]) = (destination.as_slice(), origins.as_slice()) else {
        return Err(Error::Unresolved);
    };
    // The target's subtraction names its loop-index word. Retarget the donor's
    // immediately preceding MOV index,R0 to that word. Copy its two ADD operands
    // verbatim; the existing target branch lengths still join at the same byte.
    let index = decode_insn(&code[*at + 8..], Target::H8S2000, Mode::Advanced)
        .map_err(|_| Error::Unresolved)?
        .insn;
    let mut load = decode_insn(
        source_code
            .get(from.checked_sub(2).ok_or(Error::Unresolved)?..)
            .ok_or(Error::Unresolved)?,
        Target::H8S2000,
        Mode::Advanced,
    )
    .map_err(|_| Error::Unresolved)?
    .insn;
    if index.mnemonic != "SUB"
        || load.mnemonic != "MOV"
        || !matches!(index.operands[0], Operand::Register(_))
        || index.operands[1] != load.operands[1]
    {
        return Err(Error::ResourceMismatch);
    }
    load.operands[0] = index.operands[0];
    let load = encode_insn(load, Target::H8S2000, Mode::Advanced).map_err(|_| Error::Unresolved)?;
    if load.len() != 2 {
        return Err(Error::Unresolved);
    }
    let mut changed = normal.to_vec();
    let at = before.program.start + at;
    for (to, origin) in [(at + 4, from + 4), (at + 12, from + 10)] {
        changed[to..to + 2].copy_from_slice(&load);
        changed[to + 2..to + 6].copy_from_slice(&source_code[origin..origin + 4]);
    }
    encoding::nops(&mut changed[at + 18..at + 22]).ok_or(Error::Unresolved)?;
    let after = observe(&changed)?;
    if after
        != (Binding {
            loader: Loader::Ascending,
            ..before
        })
    {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

/// Transplant a complete OEM computed loader with target helper addresses.
/// The native fetch convention and arithmetic are copied byte-for-byte except
/// declared address operands. The caller owns the unchanged-format table data.
/// DSP writer/readback bodies are verified. Arithmetic and calibration helper
/// semantics remain a separate prerequisite for whole-mechanism composition.
/// This stage cannot synthesize a loader direction absent from the donor.
pub fn transplant_computed(normal: &[u8], donor: &[u8], table: u32) -> Result<Vec<u8>, Error> {
    let (before, original, original_code) = bind(normal)?;
    let (source, shape, mut code) = bind(donor)?;
    if !before.computed
        || !source.computed
        || source.loader != Loader::AscendingNegated17
        || before.loader != source.loader
        || original.bytes != shape.bytes
        || before.spans.len() != 1
    {
        return Err(Error::ComputedUnsupported);
    }
    readback::observe(normal, before.readback, before.writer)?;
    readback::observe(donor, source.readback, source.writer)?;
    let start = table.checked_sub(0x410000).ok_or(Error::InvalidSpace)? as usize;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    if table & 1 != 0
        || !regions.stored.iter().any(|region| {
            let at = region.as_ptr() as usize - normal.as_ptr() as usize;
            start >= at
                && start
                    .checked_add(72)
                    .is_some_and(|end| end <= at + region.len())
        })
    {
        return Err(Error::InvalidSpace);
    }
    let calls: Vec<_> = original
        .fields
        .iter()
        .filter(|f| matches!(f.kind, FieldKind::Call))
        .map(|f| value(&original_code, 0, original, f.at))
        .collect::<Result<_, _>>()?;
    let mut calls = calls.into_iter();
    for field in shape.fields {
        let address = match field.kind {
            FieldKind::Call => calls.next().ok_or(Error::ResourceMismatch)?,
            FieldKind::Data => table,
            FieldKind::Literal if field.at == shape.writer => before.writer,
            _ => return Err(Error::ResourceMismatch),
        };
        crate::filters::phase::native::encoding::retarget_field(
            &mut code,
            field.at,
            field.width,
            address,
        )
        .ok_or(Error::ResourceMismatch)?;
    }
    if calls.next().is_some() || code.len() != before.program.len() {
        return Err(Error::VerificationFailed);
    }
    let mut changed = normal.to_vec();
    changed[before.program.clone()].copy_from_slice(&code);
    let after = observe(&changed)?;
    if !after.computed
        || after.loader != source.loader
        || after.program != before.program
        || after.tables != Some([Table::Literal(table); 2])
        || after.coefficient_getter != before.coefficient_getter
        || after.writer != before.writer
        || after.readback != before.readback
    {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}
