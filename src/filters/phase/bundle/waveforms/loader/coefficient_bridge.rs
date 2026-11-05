//! Complete OEM plain-loader replacement of a computed loader. Raw computed
//! basis words are never interpreted as already scaled coefficient words.
use super::*;
use crate::filters::phase::native;

/// Native replacement and the exact suffix its shorter program no longer uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Target with the donor's complete plain loader at the existing entry.
    pub image: Vec<u8>,
    /// Retired code suffix. Allocating table bytes here is a separate owner step.
    pub retired: Range<usize>,
}

/// Replace a computed routine with a complete native plain donor routine.
///
/// All declared DSP writer, readback and coefficient-extractor operands retain
/// the target's positively bound native helpers. The donor's table-selection,
/// wrapped final fetch, maximum calculation and readback tail are copied whole.
/// This transfers the complete donor loader convention; it does not claim that
/// the original computed arithmetic equals a plain table.
///
/// The caller must supply the exact associated resident Kernel, establish the
/// table contents/ownership, and prove that entry R0L denotes the donor's mode.
/// A computed caller need not initialize R0L because the old computed program
/// discards it; that caller obligation cannot be inferred from either loader.
pub fn transplant_plain(
    target: &[u8],
    donor: &[u8],
    tables: [Table; 2],
    kernel: &[u8],
) -> Result<Plan, Error> {
    let computed = computed::observe(target)?;
    let before = computed.loader;
    let (source, shape, mut code) = bind(donor)?;
    if source.computed || before.spans.len() != 1 || code.len() >= before.program.len() {
        return Err(Error::ComputedUnsupported);
    }
    readback::observe(donor, source.readback, source.writer)?;
    let source_tables = source.tables.ok_or(Error::ResourceMismatch)?;
    if source_tables[0] == source_tables[1] && tables[0] != tables[1] {
        return Err(Error::ResourceMismatch);
    }
    let emitted = before.program.start..before.program.start + code.len();
    let retired = emitted.end..before.program.end;
    native::placement::retirement_loader_references_clear(
        target,
        kernel,
        &before.program,
        &retired,
    )
    .ok_or(Error::InvalidSpace)?;
    let regions = crate::image::regions(target).ok_or(Error::Unresolved)?;
    for (old, new) in source_tables.into_iter().zip(tables) {
        let (address, size) = match (old, new) {
            (Table::Literal(_), Table::Literal(address)) => (address, 72),
            (Table::Pointer(_), Table::Pointer(address)) if address != 0 && address & 3 == 0 => {
                (address, 4)
            }
            _ => return Err(Error::ResourceMismatch),
        };
        if matches!(new, Table::Pointer(_))
            && (address < 0x410000 || address as usize >= 0x410000 + target.len())
        {
            if address > 0xffffff {
                return Err(Error::InvalidSpace);
            }
            // Live pointer slots have no Normal storage span. Their producer
            // and selected table contents are the complete owner's obligation.
            continue;
        }
        if let Some(at) = address.checked_sub(0x410000).map(|a| a as usize) {
            if address & 1 != 0
                || !regions.stored.iter().any(|region| {
                    let start = region.as_ptr() as usize - target.as_ptr() as usize;
                    start <= at && at + size <= start + region.len()
                })
                || (at < emitted.end && emitted.start < at + size)
            {
                return Err(Error::InvalidSpace);
            }
        } else if matches!(new, Table::Literal(_)) {
            return Err(Error::InvalidSpace);
        }
    }
    for field in shape.fields {
        let old = value(&code, 0, shape, field.at)?;
        let address = if shape.tables.contains(&field.at) {
            let mode = source_tables
                .iter()
                .position(|table| match table {
                    Table::Literal(address) | Table::Pointer(address) => *address == old,
                })
                .ok_or(Error::ResourceMismatch)?;
            match tables[mode] {
                Table::Literal(address) | Table::Pointer(address) => address,
            }
        } else if shape.coefficient.contains(&field.at) {
            before.coefficient_getter
        } else if field.at == shape.readback {
            before.readback
        } else if old == source.writer {
            before.writer
        } else {
            return Err(Error::ResourceMismatch);
        };
        native::encoding::retarget_field(&mut code, field.at, field.width, address)
            .ok_or(Error::ResourceMismatch)?;
    }
    let mut changed = target.to_vec();
    changed[emitted].copy_from_slice(&code);
    // Retain the unused bytes until the complete mechanism owner assigns their
    // next purpose. This stage does not clear or populate another resource.
    let actual = observe(&changed)?;
    if actual.computed
        || actual.loader != source.loader
        || actual.tables != Some(tables)
        || actual.coefficient_getter != before.coefficient_getter
        || actual.writer != before.writer
        || actual.readback != before.readback
    {
        return Err(Error::VerificationFailed);
    }
    Ok(Plan {
        image: changed,
        retired,
    })
}
