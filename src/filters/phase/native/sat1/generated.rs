//! Native four-bank SAT1 generated graph and shared evaluator resources.
//! Binding does not establish that a different output interface is correctible.
use super::*;
#[path = "generated_shapes.rs"]
mod shapes;

/// Native coefficient precision, including the exact original rounding and clamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Precision {
    /// Signed8-bit coefficients with native127/-128 clamp.
    Byte,
    /// Signed10-bit coefficients with native511/-512 clamp.
    SplitWord,
}
/// Complete shared arithmetic and calibration graph before output encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluators {
    /// Complete native arithmetic variant; never an assumed rescaling.
    pub precision: Precision,
    /// Complete first and second channel evaluator programs.
    pub programs: [Range<usize>; 2],
    /// Paired signed coefficient basis in Normal ROM.
    pub basis: Range<usize>,
    /// Complete eight-mode calibration reader.
    pub calibration: Range<usize>,
    /// Native multiply and divide service addresses.
    pub arithmetic: [u32; 2],
    /// Native persistent-word read service; this graph never writes it.
    pub parameter_reader: u32,
    /// Mode-index and fallback immediates, in native instruction order.
    pub calibration_literals: Vec<(usize, u16)>,
}
/// Full native split-word generated mechanism, including producer and command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// State-updating command called by the firmware.
    pub command: Range<usize>,
    /// Four-mode RAM-bank selector.
    pub selector: Range<usize>,
    /// Complete split-word output driver.
    pub output: Range<usize>,
    /// Complete native four-bank producer.
    pub producer: Range<usize>,
    /// Complete per-phase coefficient generation graph.
    pub evaluators: Evaluators,
    /// Runtime coefficient banks, each containing64 paired words.
    pub buffers: [u32; 4],
    /// Native state base and direction flag.
    pub state: [u32; 2],
    /// Retained resident low-byte encoding service.
    pub encoder: u32,
}

fn operand_value(op: O) -> Option<u32> {
    match op {
        O::Address(Ea::Absolute {
            value,
            bits: 24 | 32,
        })
        | O::Immediate { value, bits: 32 } => Some(value),
        _ => None,
    }
}
fn with_value(op: O, replacement: u32) -> Option<O> {
    Some(match op {
        O::Address(Ea::Absolute { bits, .. }) => O::Address(Ea::Absolute {
            value: replacement,
            bits,
        }),
        O::Immediate { bits, .. } => O::Immediate {
            value: replacement,
            bits,
        },
        _ => return None,
    })
}
struct Roles {
    code: Vec<(u32, usize, u32)>,
    values: Vec<(u32, Option<u32>)>,
}
impl Roles {
    fn new(code: Vec<(u32, usize, u32)>) -> Self {
        Self {
            code,
            values: [
                0x640ad2, 0x405ee6, 0x405e84, 0x4732cc, 0x4426, 0x44a2, 0x45a2, 0x46a2, 0x47a2,
                0x5456, 0x40528a,
            ]
            .into_iter()
            .map(|v| (v, None))
            .collect(),
        }
    }
    fn value(&self, reference: u32) -> Result<u32, Error> {
        self.values
            .iter()
            .find(|(r, _)| *r == reference)
            .and_then(|(_, v)| *v)
            .ok_or(Error::ResourceMismatch)
    }
    fn match_body(
        &mut self,
        normal: &[u8],
        at: u32,
        reference: (u32, &[u8]),
        calibration: bool,
    ) -> Result<Vec<(usize, u16)>, Error> {
        let range = stored(normal, at, reference.1.len())?;
        let actual = &normal[range];
        let mut literals = Vec::new();
        for (offset, expected, length) in decoded(reference.1)? {
            let candidate = decode_insn(&actual[offset..], Target::H8S2000, Mode::Advanced)
                .map_err(|_| Error::Unresolved)?;
            if candidate.len != length {
                return Err(Error::Unresolved);
            }
            let mut observed = candidate.insn;
            for (want, got) in expected.operands.iter().zip(observed.operands.iter_mut()) {
                if calibration
                    && expected.mnemonic == "MOV"
                    && expected.size == Some(Size::Word)
                    && matches!(expected.operands[1], O::Register(Reg::Word(0 | 8)))
                {
                    if let (O::Immediate { bits: 16, .. }, O::Immediate { value, bits: 16 }) =
                        (*want, *got)
                    {
                        literals.push((offset, value as u16));
                        *got = *want;
                        continue;
                    }
                }
                let Some(reference_value) = operand_value(*want) else {
                    continue;
                };
                let value = operand_value(*got).ok_or(Error::ResourceMismatch)?;
                if let Some(&(base, len, target)) = self
                    .code
                    .iter()
                    .find(|(base, len, _)| (*base..*base + *len as u32).contains(&reference_value))
                {
                    if value != target + (reference_value - base) {
                        return Err(Error::ResourceMismatch);
                    }
                    let _ = len;
                    *got = with_value(*got, reference_value).ok_or(Error::ResourceMismatch)?;
                } else if let Some((_, bound)) =
                    self.values.iter_mut().find(|(r, _)| *r == reference_value)
                {
                    if bound.replace(value).is_some_and(|old| old != value) {
                        return Err(Error::ResourceMismatch);
                    }
                    *got = with_value(*got, reference_value).ok_or(Error::ResourceMismatch)?;
                }
            }
            if observed != expected {
                return Err(Error::Unresolved);
            }
        }
        Ok(literals)
    }
}

/// Bind the shared native evaluator pair from already-proven caller entries.
/// RAM producer and output-interface ownership remain the caller's obligation.
pub fn observe_evaluators(
    normal: &[u8],
    first: u32,
    second: u32,
    calibration: u32,
) -> Result<Evaluators, Error> {
    for (a, b, precision) in [
        (shapes::FIRST, shapes::SECOND, Precision::SplitWord),
        (shapes::FIRST_BYTE, shapes::SECOND_BYTE, Precision::Byte),
    ] {
        if let Ok(binding) = bind_evaluators(normal, first, second, calibration, a, b, precision) {
            return Ok(binding);
        }
    }
    Err(Error::Unresolved)
}
#[allow(clippy::too_many_arguments)]
fn bind_evaluators(
    normal: &[u8],
    first: u32,
    second: u32,
    calibration: u32,
    first_shape: (u32, &[u8]),
    second_shape: (u32, &[u8]),
    precision: Precision,
) -> Result<Evaluators, Error> {
    let code = vec![
        (first_shape.0, first_shape.1.len(), first),
        (second_shape.0, second_shape.1.len(), second),
        (
            shapes::CALIBRATION.0,
            shapes::CALIBRATION.1.len(),
            calibration,
        ),
    ];
    let mut roles = Roles::new(code);
    roles.match_body(normal, first, first_shape, false)?;
    roles.match_body(normal, second, second_shape, false)?;
    let literals = roles.match_body(normal, calibration, shapes::CALIBRATION, true)?;
    let arithmetic = [roles.value(0x405ee6)?, roles.value(0x405e84)?];
    let parameter_reader = roles.value(0x4732cc)?;
    if arithmetic
        .iter()
        .any(|a| *a < 0x400000 || *a >= 0x410000 || a & 1 != 0)
        || arithmetic[0] == arithmetic[1]
        || parameter_reader & 1 != 0
    {
        return Err(Error::ResourceMismatch);
    }
    stored(normal, parameter_reader, 2)?;
    let basis = stored(normal, roles.value(0x640ad2)?, 256)?;
    for &(_, len, actual) in &roles.code {
        let program = stored(normal, actual, len)?;
        if basis.start < program.end && program.start < basis.end {
            return Err(Error::ResourceMismatch);
        }
    }
    Ok(Evaluators {
        precision,
        programs: [
            stored(normal, first, shapes::FIRST.1.len())?,
            stored(normal, second, shapes::SECOND.1.len())?,
        ],
        basis,
        calibration: stored(normal, calibration, shapes::CALIBRATION.1.len())?,
        arithmetic,
        parameter_reader,
        calibration_literals: literals,
    })
}

/// Bind complete native command, producer, selectors, evaluators and driver.
pub fn observe(normal: &[u8]) -> Result<Binding, Error> {
    let regions = crate::image::regions(normal).ok_or(Error::Unresolved)?;
    let prefix: Vec<_> = shapes::COMMAND.1[..10].iter().copied().map(Some).collect();
    let mut found = None;
    for at in crate::filters::phase::bundle::sites(normal, &regions.stored, &prefix) {
        if let Ok(binding) = bind_at(normal, at) {
            if found.as_ref().is_some_and(|previous| *previous != binding) {
                return Err(Error::Unresolved);
            }
            found = Some(binding);
        }
    }
    found.ok_or(Error::Unresolved)
}
fn bind_at(normal: &[u8], at: usize) -> Result<Binding, Error> {
    let base = 0x410000 + at as u32;
    let address = |reference| base + (reference - shapes::COMMAND.0);
    let mut roles = Roles::new(vec![(shapes::COMMAND.0, 0x97a, base)]);
    for shape in [
        shapes::COMMAND,
        shapes::FIRST,
        shapes::SECOND,
        shapes::PRODUCER,
        shapes::SELECTOR,
        shapes::CALIBRATION,
    ] {
        roles.match_body(
            normal,
            address(shape.0),
            shape,
            shape.0 == shapes::CALIBRATION.0,
        )?;
    }
    let output_template = templates::TEMPLATES
        .iter()
        .find(|t| t.interface == Interface::SplitWord && t.bytes.len() == 128)
        .ok_or(Error::Unresolved)?;
    roles.match_body(
        normal,
        address(0x57d31c),
        (0x57d31c, output_template.bytes),
        false,
    )?;
    if normal.get(stored(normal, address(0x57d308), ZERO.len())?) != Some(ZERO) {
        return Err(Error::ResourceMismatch);
    }
    let buffers = [0x44a2, 0x45a2, 0x46a2, 0x47a2]
        .map(|r| roles.value(r))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    if buffers
        .iter()
        .any(|p| *p == 0 || *p >= 0x400000 || p & 1 != 0)
        || buffers
            .windows(2)
            .any(|p| p[0].checked_add(256) != Some(p[1]))
    {
        return Err(Error::ResourceMismatch);
    }
    let evaluators = observe_evaluators(
        normal,
        address(shapes::FIRST.0),
        address(shapes::SECOND.0),
        address(shapes::CALIBRATION.0),
    )?;
    let encoder = roles.value(0x40528a)?;
    if !(0x400000..0x410000).contains(&encoder) || encoder & 1 != 0 {
        return Err(Error::ResourceMismatch);
    }
    let state = [roles.value(0x4426)?, roles.value(0x5456)?];
    if state.iter().any(|p| *p == 0 || *p >= 0x400000)
        || buffers
            .iter()
            .any(|p| state.iter().any(|s| (*p..*p + 256).contains(s)))
        || evaluators.basis.start < at + 0x97a && at < evaluators.basis.end
    {
        return Err(Error::ResourceMismatch);
    }
    Ok(Binding {
        command: stored(normal, base, shapes::COMMAND.1.len())?,
        selector: stored(
            normal,
            address(shapes::SELECTOR.0),
            shapes::SELECTOR.1.len(),
        )?,
        output: stored(normal, address(0x57d31c), 128)?,
        producer: stored(
            normal,
            address(shapes::PRODUCER.0),
            shapes::PRODUCER.1.len(),
        )?,
        evaluators,
        buffers: buffers.try_into().map_err(|_| Error::Unresolved)?,
        state,
        encoder,
    })
}

/// Validate the exact resident arithmetic and low-byte encoder called by this
/// native graph. The parameter reader remains an explicit external service.
pub fn observe_with_kernel(
    normal: &[u8],
    kernel: &[u8],
) -> Result<(Binding, super::super::arithmetic::Binding), Error> {
    if kernel.len() != crate::image::KERNEL_LEN {
        return Err(Error::ResourceMismatch);
    }
    let binding = observe(normal)?;
    let arithmetic = super::super::arithmetic::observe(
        kernel,
        0x400000,
        binding.evaluators.arithmetic[0],
        binding.evaluators.arithmetic[1],
    )
    .ok_or(Error::ResourceMismatch)?;
    let entry = binding
        .encoder
        .checked_sub(0x400000)
        .ok_or(Error::ResourceMismatch)? as usize;
    if kernel.get(entry..entry + 4) != Some(&[0x0c, 0x08, 0x54, 0x70]) {
        return Err(Error::ResourceMismatch);
    }
    Ok((binding, arithmetic))
}

/// Logical calibration ABI layered over the target's complete native read graph.
/// Physical bank layout remains the persistent-layout owner's responsibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParameterContract {
    /// Complete getter/resolver/journal graph retained in its original component.
    pub reader: crate::image::layout::H8ReaderEvidence,
    /// Logical u16 word indices in phase-calibration mode order0..7.
    pub indices: [u16; 8],
    /// Signed fallback values used only when the native read returns0xffff.
    pub defaults: [i16; 8],
}

/// Establish the complete logical parameter service used by the native phase
/// getter. The getter passes an unsigned word index in R0, receives one LE16
/// logical word in R0, tests erased0xffff, and evaluators consume signed i16.
/// No physical address or bank equivalence is inferred from matching indices.
pub fn parameter_contract(
    normal: &[u8],
    kernel: Option<&[u8]>,
    evaluators: &Evaluators,
) -> Result<ParameterContract, Error> {
    let address = |range: &Range<usize>| {
        u32::try_from(range.start)
            .ok()
            .and_then(|at| 0x410000u32.checked_add(at))
            .ok_or(Error::ResourceMismatch)
    };
    let rebound = observe_evaluators(
        normal,
        address(&evaluators.programs[0])?,
        address(&evaluators.programs[1])?,
        address(&evaluators.calibration)?,
    )?;
    if &rebound != evaluators {
        return Err(Error::Verification);
    }
    parameter_contract_at(normal, kernel, address(&evaluators.calibration)?)
}

/// Bind the same eight-mode parameter getter without requiring a separate
/// evaluator pair (the three-bank native producer inlines its arithmetic).
pub fn parameter_contract_at(
    normal: &[u8],
    kernel: Option<&[u8]>,
    calibration: u32,
) -> Result<ParameterContract, Error> {
    use crate::image::layout::{
        self, H8ReaderComponent, Observation, ParameterLayout, WordEncoding,
    };
    let mut roles = Roles::new(vec![(
        shapes::CALIBRATION.0,
        shapes::CALIBRATION.1.len(),
        calibration,
    )]);
    let literals = roles.match_body(normal, calibration, shapes::CALIBRATION, true)?;
    let parameter_reader = roles.value(0x4732cc)?;
    let Observation::Known(reader) = layout::discover_h8_reader(normal, kernel) else {
        return Err(Error::ResourceMismatch);
    };
    if reader.component != H8ReaderComponent::Normal
        || reader.getter != parameter_reader
        || reader.argument_register != 0
        || literals.len() != 16
    {
        return Err(Error::ResourceMismatch);
    }
    let ParameterLayout::FlashRecords {
        domains, encoding, ..
    } = &reader.layout
    else {
        return Err(Error::ResourceMismatch);
    };
    if !matches!(
        encoding,
        WordEncoding::LittleEndian | WordEncoding::DirectOrBusPermutedLittleEndian
    ) {
        return Err(Error::ResourceMismatch);
    }
    // These offsets belong to the exact bound native branch graph. They are
    // kept explicit so a flattened list cannot erase the mode-to-index relation.
    let fields = [
        (44, 62),
        (70, 88),
        (96, 114),
        (122, 138),
        (144, 160),
        (166, 182),
        (188, 204),
        (210, 226),
    ];
    let mut indices = [0; 8];
    let mut defaults = [0; 8];
    for (reverse_mode, ((index_at, default_at), literals)) in
        fields.into_iter().zip(literals.chunks_exact(2)).enumerate()
    {
        if literals[0].0 != index_at || literals[1].0 != default_at {
            return Err(Error::ResourceMismatch);
        }
        let parameter = literals[0].1;
        if !domains
            .iter()
            .any(|d| d.first <= parameter && parameter <= d.last)
        {
            return Err(Error::ResourceMismatch);
        }
        indices[7 - reverse_mode] = parameter;
        defaults[7 - reverse_mode] = literals[1].1 as i16;
    }
    Ok(ParameterContract {
        reader,
        indices,
        defaults,
    })
}
