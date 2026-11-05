//! Complete native H8 DSP waveform-loader binding and canonical emission.
use crate::filters::phase::bundle::{sites, Loader, Template};
use alloc::vec::Vec;
use core::ops::Range;
mod shapes;
/// Complete DSP write-helper ABI proof.
pub mod writer;

#[derive(Clone, Copy)]
enum FieldKind {
    Call,
    Literal,
    Ram,
    Data,
}
struct Field {
    at: usize,
    width: usize,
    kind: FieldKind,
}
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
    /// Exact stored program range in decoded Normal.
    pub program: Range<usize>,
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
fn bind(normal: &[u8]) -> Result<(Binding, &'static Shape), Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let mut found = None;
    for shape in shapes::SHAPES {
        for at in sites(normal, &regions.stored, shape.bytes) {
            if found.is_some() {
                return Err(Error::Unresolved);
            }
            let get = |offset| value(normal, at, shape, offset);
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
                    && normal.get(at + field.at - 3..at + field.at - 1) == Some(&[0x0d, 0x38][..])
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
                    program: at..at + shape.bytes.len(),
                    loader: shape.loader,
                    tables,
                    computed: shape.computed,
                    coefficient_getter: coefficient,
                    writer,
                    readback,
                },
                shape,
            ));
        }
    }
    found.ok_or(Error::Unresolved)
}
/// Bind the entire loader program, never only its address-selection snippet.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    Ok(bind(normal)?.0)
}

/// Emit the plain paired-word loader using target's own getter/writer/reader.
/// The caller supplies already-normalized image-resident tables in mode order
/// and separately owns their data. Computed programs require an explicit native
/// donor via `transplant_computed`. No table, checksum,
/// or persistent setting is written by this stage.
pub fn rewrite(
    normal: &[u8],
    direction: Loader,
    tables: [u32; 2],
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let before = observe(normal)?;
    if before.computed {
        return Err(Error::ComputedUnsupported);
    }
    let shape = shapes::SHAPES
        .iter()
        .find(|s| {
            !s.computed
                && s.loader == direction
                && s.bytes.len() == 184
                && s.tables.len() == 2
                && s.bytes[8..10] == [Some(0x1a), Some(0xb3)]
        })
        .ok_or(Error::Unresolved)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let contains = |span: &Range<usize>| {
        regions.stored.iter().any(|r| {
            let at = r.as_ptr() as usize - normal.as_ptr() as usize;
            span.start >= at && span.end <= at + r.len()
        })
    };
    for address in tables {
        let at = address.checked_sub(0x410000).ok_or(Error::InvalidSpace)? as usize;
        if address & 1 != 0 || !contains(&(at..at + 72)) {
            return Err(Error::InvalidSpace);
        }
    }
    let mut code: Vec<_> = shape.bytes.iter().map(|b| b.unwrap_or(0)).collect();
    for field in shape.fields {
        let address = if field.at == shape.tables[0] {
            tables[1]
        } else if field.at == shape.tables[1] {
            tables[0]
        } else if shape.coefficient.contains(&field.at) {
            before.coefficient_getter
        } else if field.at == shape.writer {
            before.writer
        } else if field.at == shape.readback {
            before.readback
        } else {
            return Err(Error::ResourceMismatch);
        };
        code[field.at..field.at + field.width]
            .copy_from_slice(&address.to_be_bytes()[4 - field.width..]);
    }
    let mut changed = normal.to_vec();
    if code.len() <= before.program.len() {
        changed[before.program.clone()].fill(0);
        changed[before.program.start..before.program.start + code.len()].copy_from_slice(&code);
    } else {
        let space = reservation.ok_or(Error::SpaceRequired)?;
        if space.start & 1 != 0
            || space.end & 1 != 0
            || space.start > space.end
            || space.len() < code.len()
            || !contains(&space)
            || (space.start < before.program.end && before.program.start < space.end)
            || !normal
                .get(space.clone())
                .is_some_and(|b| b.iter().all(|b| *b == 0xff))
        {
            return Err(Error::InvalidSpace);
        }
        let address = 0x410000usize
            .checked_add(space.start)
            .filter(|a| *a <= 0xffffff)
            .ok_or(Error::InvalidSpace)? as u32;
        changed[before.program.start..before.program.start + 4].copy_from_slice(&[
            0x5a,
            address.to_be_bytes()[1],
            address.to_be_bytes()[2],
            address.to_be_bytes()[3],
        ]);
        changed[space.clone()].fill(0);
        changed[space.start..space.start + code.len()].copy_from_slice(&code);
    }
    let after = observe(&changed)?;
    if after.loader != direction
        || after.tables != Some(tables.map(Table::Literal))
        || after.coefficient_getter != before.coefficient_getter
        || after.writer != before.writer
        || after.readback != before.readback
    {
        return Err(Error::VerificationFailed);
    }
    Ok(changed)
}

/// Transplant a recognized noncomputed OEM loader without changing its fetch
/// algorithm. Only declared helper/table address operands are relocated. Pointer
/// slots retain pointer semantics; their initialization and live prerequisites
/// belong to the caller. Table bytes and image integrity are not changed here.
pub fn transplant_plain(
    normal: &[u8],
    donor: &[u8],
    tables: [Table; 2],
    reservation: Option<Range<usize>>,
) -> Result<Vec<u8>, Error> {
    let before = observe(normal)?;
    let (source, shape) = bind(donor)?;
    if before.computed || source.computed {
        return Err(Error::ComputedUnsupported);
    }
    writer::observe(normal, before.writer)?;
    writer::observe(donor, source.writer)?;
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
    let mut code = donor[source.program.clone()].to_vec();
    for field in shape.fields {
        let address = if shape.tables.contains(&field.at) {
            let old = value(donor, source.program.start, shape, field.at)?;
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
        } else if value(donor, source.program.start, shape, field.at)? == source.writer {
            before.writer
        } else {
            return Err(Error::ResourceMismatch);
        };
        code[field.at..field.at + field.width]
            .copy_from_slice(&address.to_be_bytes()[4 - field.width..]);
    }
    let destination = if code.len() <= before.program.len() {
        before.program.clone()
    } else {
        reservation.clone().ok_or(Error::SpaceRequired)?
    };
    for table in tables {
        if let Table::Literal(address) = table {
            let at = (address - 0x410000) as usize;
            if destination.start < at + 72 && at < destination.end {
                return Err(Error::InvalidSpace);
            }
        }
    }
    let mut changed = normal.to_vec();
    if code.len() <= before.program.len() {
        changed[before.program.clone()].fill(0);
        changed[before.program.start..before.program.start + code.len()].copy_from_slice(&code);
    } else {
        let space = reservation.ok_or(Error::SpaceRequired)?;
        if space.start & 1 != 0
            || space.end & 1 != 0
            || space.start > space.end
            || space.len() < code.len()
            || !contains(&space)
            || (space.start < before.program.end && before.program.start < space.end)
            || !normal
                .get(space.clone())
                .is_some_and(|bytes| bytes.iter().all(|b| *b == 0xff))
        {
            return Err(Error::InvalidSpace);
        }
        let address = 0x410000usize
            .checked_add(space.start)
            .filter(|a| *a <= 0xffffff)
            .ok_or(Error::InvalidSpace)? as u32;
        changed[before.program.start..before.program.start + 4].copy_from_slice(&[
            0x5a,
            address.to_be_bytes()[1],
            address.to_be_bytes()[2],
            address.to_be_bytes()[3],
        ]);
        changed[space.clone()].fill(0);
        changed[space.start..space.start + code.len()].copy_from_slice(&code);
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

/// Transplant a complete OEM computed loader with target helper addresses.
/// The native fetch convention and arithmetic are copied byte-for-byte except
/// declared address operands. The caller owns the unchanged-format table data.
/// This stage cannot synthesize a loader direction absent from the donor.
pub fn transplant_computed(normal: &[u8], donor: &[u8], table: u32) -> Result<Vec<u8>, Error> {
    let (before, original) = bind(normal)?;
    let (source, shape) = bind(donor)?;
    if !before.computed
        || !source.computed
        || source.loader != Loader::AscendingNegated17
        || before.loader != source.loader
        || original.bytes != shape.bytes
    {
        return Err(Error::ComputedUnsupported);
    }
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
        .map(|f| value(normal, before.program.start, original, f.at))
        .collect::<Result<_, _>>()?;
    let mut calls = calls.into_iter();
    let mut code = donor[source.program.clone()].to_vec();
    for field in shape.fields {
        let address = match field.kind {
            FieldKind::Call => calls.next().ok_or(Error::ResourceMismatch)?,
            FieldKind::Data => table,
            FieldKind::Literal if field.at == shape.writer => before.writer,
            _ => return Err(Error::ResourceMismatch),
        };
        code[field.at..field.at + field.width]
            .copy_from_slice(&address.to_be_bytes()[4 - field.width..]);
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
