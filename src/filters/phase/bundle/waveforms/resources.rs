//! Bind motion and coefficient tables by complete native consumers and branches.
//! Pointer selection describes a read-only prerequisite, never a persistent write.
use super::loader::{self, Table};
use crate::filters::phase::bundle::{self, sites, Template};
use crate::filters::phase::native;
use crate::image::layout::Observation;
use alloc::vec::Vec;
use core::ops::Range;
/// Transfer a complete native calibration source without persistent writes.
pub mod calibration_bridge;
/// Native generated-waveform basis and evaluator relationships.
pub mod evaluators;
/// Complete generated-table phase graph and convention transfer.
pub mod generated;
mod shapes;
/// Software-table dispatch and selector observation; generation proof is separate.
pub mod software;

/// Why the native resource graph could not be established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A complete unique consumer or initializer is missing.
    Unresolved,
    /// Consumers disagree on a local resource or a table is not stored.
    ResourceMismatch,
}

/// Four image tables selected by one native execution branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tables {
    /// The two 64-row paired-word motion tables, in native selector order.
    pub motion: [Range<usize>; 2],
    /// The two 18-row paired-word DSP tables, in zero/nonzero mode order.
    pub coefficients: [Range<usize>; 2],
}

/// Complete native table-role graph, independent of family admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// Complete step-dispatch program.
    pub dispatch: Range<usize>,
    /// Complete initializer when the dispatch loads RAM pointers.
    pub initializer: Option<Range<usize>>,
    /// Ordinary tables, or parameter 0x28F's non-FFFF branch.
    pub selected: Tables,
    /// Parameter 0x28F's FFFF branch, if present.
    pub erased_parameter: Option<Tables>,
}

/// Motion roles established without assuming a DSP loader is present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiteralMotion {
    /// Whole native step dispatcher.
    pub dispatch: Range<usize>,
    /// Ordinary dispatch table, separate from the two special motion roles.
    pub ordinary: Range<usize>,
    /// Motion tables selected by the two native predicates.
    pub motion: [Range<usize>; 2],
}

/// Bind a complete literal-table dispatcher independently of DSP discovery.
/// This observation proves table consumers, not that other mechanism elements
/// are absent or that the complete phase convention can be corrected.
pub fn observe_literal_motion(normal: &[u8]) -> Result<LiteralMotion, Error> {
    let Observation::Known(coils) = native::discover_pair(normal) else {
        return Err(Error::Unresolved);
    };
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    bundle::step_source(normal, &regions.stored, &coils).map_err(|_| Error::Unresolved)?;
    let matches = sites(normal, &regions.stored, shapes::STATIC_DISPATCH);
    let [at] = matches.as_slice() else {
        return Err(Error::Unresolved);
    };
    let body = &normal[*at..*at + shapes::STATIC_DISPATCH.len()];
    let first = bundle::resolve_call(normal, call(body, 79)).ok_or(Error::ResourceMismatch)?;
    let last = bundle::resolve_call(normal, call(body, 159)).ok_or(Error::ResourceMismatch)?;
    if first == last
        || !coils.functions.contains(&first)
        || !coils.functions.contains(&last)
        || [99, 135]
            .into_iter()
            .any(|offset| bundle::resolve_call(normal, call(body, offset)) != Some(first))
        || word(body, 68) != word(body, 126)
    {
        return Err(Error::ResourceMismatch);
    }
    ram(word(body, 68))?;
    Ok(LiteralMotion {
        dispatch: *at..*at + shapes::STATIC_DISPATCH.len(),
        ordinary: table(normal, word(body, 40), 256)?,
        motion: [
            table(normal, word(body, 56), 256)?,
            table(normal, word(body, 90), 256)?,
        ],
    })
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(bytes[at..at + 4].try_into().expect("bound field"))
}
fn call(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([0, bytes[at], bytes[at + 1], bytes[at + 2]])
}
fn ram(address: u32) -> Result<(), Error> {
    if address == 0 || address & 1 != 0 || address >= 0x100000 {
        return Err(Error::ResourceMismatch);
    }
    Ok(())
}
fn table(normal: &[u8], address: u32, size: usize) -> Result<Range<usize>, Error> {
    let start = address
        .checked_sub(0x410000)
        .ok_or(Error::ResourceMismatch)? as usize;
    let end = start.checked_add(size).ok_or(Error::ResourceMismatch)?;
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    if address & 1 != 0
        || !regions.stored.iter().any(|region| {
            let at = region.as_ptr() as usize - normal.as_ptr() as usize;
            start >= at && end <= at + region.len()
        })
    {
        return Err(Error::ResourceMismatch);
    }
    Ok(start..end)
}
/// Resolve only stored image pointer cells. A RAM pointer still needs the
/// complete native initializer and cannot be treated as an image address.
fn literal_table(normal: &[u8], source: Table) -> Result<u32, Error> {
    match source {
        Table::Literal(address) => {
            table(normal, address, 72)?;
            Ok(address)
        }
        Table::Pointer(address) => {
            let cell = table(normal, address, 4)?;
            let value =
                h8_asm::image::read_u32(normal, cell.start).ok_or(Error::ResourceMismatch)?;
            table(normal, value, 72)?;
            Ok(value)
        }
    }
}

fn tables(normal: &[u8], addresses: [u32; 4]) -> Result<Tables, Error> {
    let result = Tables {
        motion: [
            table(normal, addresses[0], 256)?,
            table(normal, addresses[1], 256)?,
        ],
        coefficients: [
            table(normal, addresses[2], 72)?,
            table(normal, addresses[3], 72)?,
        ],
    };
    let ranges: Vec<_> = result.motion.iter().chain(&result.coefficients).collect();
    for (i, a) in ranges.iter().enumerate() {
        for b in &ranges[i + 1..] {
            if a.start < b.end && b.start < a.end && !(i == 2 && *a == *b) {
                return Err(Error::ResourceMismatch);
            }
        }
    }
    Ok(result)
}

/// Bind whole step-dispatch programs through both native coil callees, then
/// connect their motion roles to the complete DSP loader and initializer.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    let Observation::Known(coils) = native::discover_pair(normal) else {
        return Err(Error::Unresolved);
    };
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    // This also proves both full-step blocks, whose constants vary in the grammar.
    bundle::step_source(normal, &regions.stored, &coils).map_err(|_| Error::Unresolved)?;
    let loader = loader::observe(normal).map_err(|_| Error::Unresolved)?;
    let mut found = None;
    for (pointer, shape, calls, slots, state) in [
        (
            false,
            shapes::STATIC_DISPATCH,
            &[79usize, 99, 135, 159][..],
            [68, 126],
            [10, 20],
        ),
        (
            true,
            shapes::POINTER_DISPATCH,
            &[47usize, 87, 111, 131, 173, 197][..],
            [100, 164],
            [10, 22],
        ),
    ] {
        for at in sites(normal, &regions.stored, shape) {
            if found.is_some() {
                return Err(Error::Unresolved);
            }
            let bytes = &normal[at..at + shape.len()];
            let first = bundle::resolve_call(normal, call(bytes, calls[0]))
                .ok_or(Error::ResourceMismatch)?;
            let last = bundle::resolve_call(normal, call(bytes, *calls.last().expect("calls")))
                .ok_or(Error::ResourceMismatch)?;
            if first == last
                || !coils.functions.contains(&first)
                || !coils.functions.contains(&last)
                || calls[..calls.len() - 1]
                    .iter()
                    .any(|offset| bundle::resolve_call(normal, call(bytes, *offset)) != Some(first))
                || word(bytes, slots[0]) != word(bytes, slots[1])
            {
                return Err(Error::ResourceMismatch);
            }
            ram(word(bytes, slots[0]))?;
            for offset in state {
                let address = word(bytes, offset);
                if address == 0 || address >= 0x100000 {
                    return Err(Error::ResourceMismatch);
                }
            }
            let dispatch = at..at + shape.len();
            let result = if pointer {
                let motion_slots = [word(bytes, 40), word(bytes, 124)];
                if motion_slots != [word(bytes, 54), word(bytes, 138)] {
                    return Err(Error::ResourceMismatch);
                }
                table(normal, word(bytes, 78), 256)?;
                let initializers = sites(normal, &regions.stored, shapes::INITIALIZER);
                let [init] = initializers.as_slice() else {
                    return Err(Error::Unresolved);
                };
                let body = &normal[*init..*init + shapes::INITIALIZER.len()];
                let expected_slots = [
                    motion_slots[0],
                    motion_slots[1],
                    word(body, 52),
                    word(body, 116),
                ];
                for (i, slot) in expected_slots.into_iter().enumerate() {
                    ram(slot)?;
                    if expected_slots[i + 1..].iter().any(|other| {
                        slot < other.saturating_add(4) && *other < slot.saturating_add(4)
                    }) {
                        return Err(Error::ResourceMismatch);
                    }
                }
                if [word(body, 24), word(body, 38)] != motion_slots
                    || [word(body, 74), word(body, 88), word(body, 102)] != expected_slots[..3]
                {
                    return Err(Error::ResourceMismatch);
                }
                let selected = [word(body, 16), word(body, 30)];
                let erased = [word(body, 66), word(body, 80)];
                let sources = loader.tables.ok_or(Error::ResourceMismatch)?;
                let (coefficients, erased_coefficients) = match sources {
                    [Table::Pointer(a), Table::Pointer(b)] if a < 0x100000 && b < 0x100000 => {
                        if [a, b] != expected_slots[2..] {
                            return Err(Error::ResourceMismatch);
                        }
                        (
                            [word(body, 44), word(body, 58)],
                            [word(body, 94), word(body, 108)],
                        )
                    }
                    [a, b] => {
                        let values = [literal_table(normal, a)?, literal_table(normal, b)?];
                        (values, values)
                    }
                };
                Binding {
                    dispatch,
                    initializer: Some(*init..*init + shapes::INITIALIZER.len()),
                    selected: tables(
                        normal,
                        [selected[0], selected[1], coefficients[0], coefficients[1]],
                    )?,
                    erased_parameter: Some(tables(
                        normal,
                        [
                            erased[0],
                            erased[1],
                            erased_coefficients[0],
                            erased_coefficients[1],
                        ],
                    )?),
                }
            } else {
                table(normal, word(bytes, 40), 256)?;
                let [a, b] = loader.tables.ok_or(Error::ResourceMismatch)?;
                let a = literal_table(normal, a)?;
                let b = literal_table(normal, b)?;
                Binding {
                    dispatch,
                    initializer: None,
                    selected: tables(normal, [word(bytes, 56), word(bytes, 90), a, b])?,
                    erased_parameter: None,
                }
            };
            // Fixed pointer cells are read-only resources too. They must not
            // overlap a consumed table or a bound program that composition edits.
            if let Some(sources) = loader.tables {
                for source in sources {
                    let Table::Pointer(address) = source else {
                        continue;
                    };
                    if address < 0x100000 {
                        continue;
                    }
                    let cell = table(normal, address, 4)?;
                    let protected = core::iter::once(&result.dispatch)
                        .chain(&loader.spans)
                        .chain(&result.initializer)
                        .chain(
                            core::iter::once(&result.selected)
                                .chain(&result.erased_parameter)
                                .flat_map(|tables| {
                                    tables.motion.iter().chain(&tables.coefficients)
                                }),
                        );
                    if protected
                        .into_iter()
                        .any(|span| cell.start < span.end && span.start < cell.end)
                    {
                        return Err(Error::ResourceMismatch);
                    }
                }
            }
            found = Some(result);
        }
    }
    found.ok_or(Error::Unresolved)
}
