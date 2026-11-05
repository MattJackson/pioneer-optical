//! Sled mechanism convention bundle bound from native Normal code.
//!
//! In H8 split-word firmware the coil output mapping (F910–F913) is only one
//! element of the mechanism convention. Firmware built for the opposite sled
//! convention also mirrors the per-channel full-step index offsets, the DSP
//! waveform loader address order, the conversions of persistent parameter
//! words 0x127/0x128, the sign of the mode-one 0x127 consumer and the
//! controller 0xEC mode bit; some images also select waveform tables through
//! parameter 0x28F. A coil-only rewrite leaves every other element in the
//! target's convention, so phase is only correctable when every element is
//! bound and all elements other than the coil mapping already agree.
//!
//! Each element is bound by an exact native code template (call targets are
//! holes) from the stored Normal regions. Zero matches is unbound; matches of
//! more than one template, or more than one site where exactly one is native,
//! are unresolved. No element is ever defaulted.

/// Atomic composition of native mechanism rewrite stages.
pub mod composition;
/// Native parameter-conversion rewrite stage; full mechanism composition is separate.
pub mod conversions;

use super::native::{self, Assignment};
use crate::image::layout::Observation;
use alloc::vec::Vec;

/// One mechanism-convention element of the bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Element {
    /// Complete paired coil output functions (F910–F913).
    Coil,
    /// Per-channel full-step index offset block calling both coil functions.
    StepOffsets,
    /// DSP waveform coefficient loader address order.
    DspLoader,
    /// Parameter 0x127/0x128 position conversion (base routine).
    CalibrationBase,
    /// Parameter 0x127/0x128 scaled-offset conversion.
    CalibrationOffset,
    /// Parameter 0x127 mode-dependent step conversion.
    CalibrationStep,
    /// Mode-one 0x127 consumer sign.
    ModeSign,
    /// Controller register 0xEC mode bit selection.
    ControllerMode,
}

/// Why a bundle could not be bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unbound {
    /// No native site of the element was found.
    Missing(Element),
    /// Several sites or several conventions of the element were found.
    Ambiguous(Element),
}

/// Typed convention of every bound bundle element. Numeric template identifiers
/// are local to this module; equal values mean byte-identical native semantics
/// modulo call targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bundle {
    /// Source/output assignment of the coil functions.
    pub coil: Assignment,
    /// Source word (0 or 1) whose coil function receives the negative
    /// (−8, {0x10, 0x30}) full-step offset.
    pub step_minus_source: u8,
    /// DSP loader address order.
    pub loader: Loader,
    /// Template of the 0x127/0x128 base conversion.
    pub calibration_base: u8,
    /// Template of the 0x127/0x128 scaled-offset conversion.
    pub calibration_offset: u8,
    /// Template of the 0x127 step conversion.
    pub calibration_step: u8,
    /// Mode-one 0x127 consumer: 0 plain, 1 negated.
    pub mode_sign: u8,
    /// Controller mode word for mode one: 0 = 0xEC88/0x08, 1 = 0xEC08/0x88.
    pub controller_mode: u8,
    /// Whether waveform tables are selected by persistent parameter 0x28F.
    pub table_select_0x28f: bool,
}

/// DSP waveform loader address order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Loader {
    /// Entry i written to 0x12A+i / 0x602+i.
    Ascending,
    /// Ascending with entry 0x11 written as the negated first coefficient.
    AscendingNegated17,
    /// Entry i written to 0x613−i / 0x132−i+9.
    Descending,
}

impl Bundle {
    /// Every element except the coil mapping.
    pub fn without_coil(self) -> [u8; 8] {
        let loader = match self.loader {
            Loader::Ascending => 0,
            Loader::AscendingNegated17 => 1,
            Loader::Descending => 2,
        };
        [
            self.step_minus_source,
            loader,
            self.calibration_base,
            self.calibration_offset,
            self.calibration_step,
            self.mode_sign,
            self.controller_mode,
            u8::from(self.table_select_0x28f),
        ]
    }
}

/// Byte template; `None` is a call-target hole.
type Template = &'static [Option<u8>];

macro_rules! t {
    (@ _) => { None };
    (@ $b:literal) => { Some($b) };
    ($($x:tt)*) => { &[$(t!(@ $x)),*] };
}

/// Native waveform fetch normalization and complete loader binding.
pub mod waveforms;

// Parameter 0x127/0x128 base conversion: (p127·16)/0x12 + p128·64 + arg, or
// its mirror 0x40 − (p127·16)/0x12 − p128·64 + arg.
const BASE: [Template; 2] = [
    t!(0x01 0x00 0x6d 0xf3 0x0d 0x1b 0x79 0x00 0x01 0x28 0x5e _ _ _ 0x0d 0x03 0x79 0x00 0x01 0x27 0x5e _ _ _
       0x10 0x50 0x10 0x50 0x17 0x70 0x79 0x02 0x00 0x12 0x53 0x20 0x10 0x53 0x10 0x53 0x10 0x53
       0x09 0x30 0x09 0xb0 0x01 0x00 0x6d 0x73 0x54 0x70),
    t!(0x01 0x00 0x6d 0xf3 0x0d 0x13 0x79 0x00 0x01 0x28 0x5e _ _ _ 0x0d 0x0b 0x79 0x00 0x01 0x27 0x5e _ _ _
       0x0d 0x39 0x79 0x01 0x00 0x40 0x10 0x50 0x10 0x50 0x17 0x70 0x79 0x03 0x00 0x12 0x53 0x30
       0x19 0x01 0x17 0x9b 0x10 0x5b 0x10 0x5b 0x10 0x5b 0x09 0xb1 0x09 0x91 0x0d 0x10
       0x01 0x00 0x6d 0x73 0x54 0x70),
];
const OFFSET: [Template; 3] = [
    t!(0x5e _ _ _ 0x5e _ _ _ 0x17 0x50 0x79 0x60 0x00 0x3f 0x79 0x01 0x00 0x12 0x52 0x10 0x11 0x50
       0x11 0x50 0x0d 0x08 0x79 0x00 0x01 0x27 0x5e _ _ _ 0x5e _ _ _ 0x11 0x50 0x11 0x50 0x11 0x50
       0x0d 0x08 0x79 0x00 0x01 0x28 0x5e _ _ _ 0x54 0x70),
    t!(0x5e _ _ _ 0x5e _ _ _ 0x0c 0x89 0x17 0x51 0x79 0x00 0x00 0x30 0x19 0x10 0x79 0x60 0x00 0x3f
       0x79 0x01 0x00 0x12 0x52 0x10 0x11 0x50 0x11 0x50 0x0d 0x08 0x79 0x00 0x01 0x27 0x5e _ _ _
       0x5e _ _ _ 0x11 0x50 0x11 0x50 0x11 0x50 0x17 0x90 0x0d 0x08 0x79 0x00 0x01 0x28 0x5e _ _ _
       0x54 0x70),
    t!(0x5e _ _ _ 0x5e _ _ _ 0x17 0x50 0x79 0x08 0x00 0x40 0x19 0x08 0x79 0x18 0x00 0x10 0x79 0x68
       0x00 0x3f 0x0d 0x80 0x79 0x01 0x00 0x12 0x52 0x10 0x11 0x50 0x11 0x50 0x0d 0x08 0x79 0x00
       0x01 0x27 0x5e _ _ _ 0x5e _ _ _ 0x11 0x50 0x11 0x50 0x11 0x50 0x17 0x90 0x0d 0x08 0x79 0x00
       0x01 0x28 0x5e _ _ _ 0x54 0x70),
];
const STEP: [Template; 3] = [
    t!(0x6d 0xf3 0x79 0x00 0x01 0x27 0x5e _ _ _ 0x0d 0x03 0x5e _ _ _ 0x0f 0x82 0x10 0x53 0x10 0x53
       0x0d 0x30 0x17 0x70 0x79 0x01 0x00 0x12 0x53 0x10 0x0c 0x89 0xe9 0x3f 0x0f 0xa0 0x5e _ _ _
       0x6d 0x73 0x54 0x70),
    t!(0x6d 0xf3 0x79 0x00 0x01 0x27 0x5e _ _ _ 0x0d 0x03 0x5e _ _ _ 0x0f 0x82 0xf9 0x40 0x10 0x53
       0x10 0x53 0x0d 0x30 0x17 0x70 0x79 0x03 0x00 0x12 0x53 0x30 0x18 0x89 0x89 0xf0 0xe9 0x3f
       0x0f 0xa0 0x5e _ _ _ 0x6d 0x73 0x54 0x70),
    t!(0x6d 0xf3 0x79 0x00 0x01 0x27 0x5e _ _ _ 0x0d 0x03 0x5e _ _ _ 0x0f 0x82 0x10 0x53 0x10 0x53
       0x0d 0x30 0x17 0x70 0x79 0x01 0x00 0x12 0x53 0x10 0x0c 0x81 0x81 0xf0 0xe1 0x3f 0xf9 0x40
       0x18 0x19 0x0f 0xa0 0x5e _ _ _ 0x6d 0x73 0x54 0x70),
];
const LOADER_ASCENDING: Template =
    t!(0xac 0x09 0x44 0x06 0x79 0x10 0x01 0x2a 0x40 0x04 0x79 0x10 0x06 0x02);
// Complete address-selection block after an in-place descending-to-ascending
// conversion. Both branches assign R0 from the loop index before adding the
// ascending DSP address. The retained NOPs are part of this native grammar.
const LOADER_ASCENDING_PADDED: Template = t!(0xac 0x09 0x44 0x08 0x0d 0xc0 0x79 0x10 0x01 0x2a 0x40 0x0a
    0x0d 0xc0 0x79 0x10 0x06 0x02 0x00 0x00 0x00 0x00);
const LOADER_DESCENDING: Template = t!(0xac 0x09 0x44 0x08 0x79 0x00 0x06 0x13 0x19 0xc0 0x40 0x0a
    0x79 0x00 0x01 0x32 0x19 0xc0 0x79 0x10 0x00 0x09);
// CMP.B #0x11,R4L; BNE; MOV.W @ER5,R0; NEG.W R0 — entry 0x11 special case.
const LOADER_NEGATED_17: Template = t!(0xac 0x11 0x46 _ 0x69 0x50 0x17 0x90);
// Complete two-branch mode programs through their common arithmetic join.
const MODE: [Template; 2] = [
    t!(0x79 0x00 0x01 0x27 0xae 0x01 0x46 0x24 0x5e _ _ _ 0x0d 0x01 0x0f 0xd0 0x0d 0xb9 0x5e _ _ _ 0x0d 0x08 0x79 0x20 0x00 0x1b 0x45 0x06 0x79 0x00 0x00 0x63 0x40 0x04 0x79 0x00 0x00 0x1b 0x19 0x80 0x40 0x20 0x5e _ _ _ 0x0d 0x01 0x17 0x9b 0x0d 0xb9 0x0f 0xd0 0x5e _ _ _ 0x79 0x20 0x00 0x1b 0x45 0x06 0x79 0x30 0x00 0x1b 0x40 0x04 0x79 0x10 0x00 0x2d),
    t!(0x79 0x00 0x01 0x27 0xae 0x01 0x46 0x22 0x5e _ _ _ 0x0d 0x01 0x17 0x9b 0x0d 0xb9 0x0f 0xd0 0x5e _ _ _ 0x79 0x20 0x00 0x1b 0x45 0x06 0x79 0x30 0x00 0x1b 0x40 0x28 0x79 0x10 0x00 0x2d 0x40 0x22 0x5e _ _ _ 0x0d 0x01 0x0f 0xd0 0x0d 0xb9 0x5e _ _ _ 0x0d 0x08 0x79 0x20 0x00 0x1b 0x45 0x06 0x79 0x00 0x00 0x63 0x40 0x04 0x79 0x00 0x00 0x1b 0x19 0x80),
];
const CONTROLLER: [Template; 2] = [
    t!(0x79 0x00 0xec 0x88 0xae 0x01 0x46 0x02 0xf8 0x08),
    t!(0x79 0x00 0xec 0x08 0xae 0x01 0x46 0x02 0xf8 0x88),
];
const TABLE_SELECT: Template = t!(0x79 0x00 0x02 0x8f 0x5e _ _ _);
// MOV.B RnL,R0L; ADD.B #±8,R0L; AND.B #0x3F; CMP.B #0x20; BCC; low; BRA; high.
const STEP_PLUS: Template =
    t!(0x0c _ 0x88 0x08 0xe8 0x3f 0xa8 0x20 0x44 0x04 0x18 0x88 0x40 0x02 0xf8 0x20);
const STEP_MINUS: Template =
    t!(0x0c _ 0x88 0xf8 0xe8 0x3f 0xa8 0x20 0x44 0x04 0xf8 0x10 0x40 0x02 0xf8 0x30);

fn masked(template: &[Option<u8>]) -> Vec<(u16, u16)> {
    template
        .chunks(2)
        .map(|pair| {
            let byte = |at: usize| pair.get(at).copied().flatten();
            (
                u16::from_be_bytes([byte(0).unwrap_or(0), byte(1).unwrap_or(0)]),
                u16::from_be_bytes([
                    if byte(0).is_some() { 255 } else { 0 },
                    if byte(1).is_some() { 255 } else { 0 },
                ]),
            )
        })
        .collect()
}

/// Even stored-region offsets where `template` matches through h8-asm.
pub(super) fn sites(normal: &[u8], stored: &[&[u8]], template: &[Option<u8>]) -> Vec<usize> {
    let mut found = Vec::new();
    if template.is_empty() || template.len() % 2 != 0 {
        return found;
    }
    let pattern = masked(template);
    for region in stored {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        let skip = start & 1;
        let Some(aligned) = region.get(skip..) else {
            continue;
        };
        let mut cursor = 0;
        while let Some(at) =
            h8_asm::image::find(aligned, h8_asm::image::Needle::Masked(&pattern), cursor)
        {
            found.push(start + skip + at);
            cursor = at + 2;
        }
    }
    found
}

/// Exactly one site of exactly one template; returns the template index.
fn one_of(
    normal: &[u8],
    stored: &[&[u8]],
    templates: &[Template],
    element: Element,
) -> Result<(u8, usize), Unbound> {
    if matches!(
        element,
        Element::CalibrationBase | Element::CalibrationOffset | Element::CalibrationStep
    ) {
        return conversions::locate(normal, stored, templates, element)
            .map(|(variant, at, _)| (variant, at));
    }
    let mut hit = None;
    for (index, template) in templates.iter().enumerate() {
        for at in sites(normal, stored, template) {
            if hit.is_some() {
                return Err(Unbound::Ambiguous(element));
            }
            hit = Some((index as u8, at));
        }
    }
    hit.ok_or(Unbound::Missing(element))
}

const BASE_ADDRESS: usize = 0x410000;

/// Resolve a JSR target to a decoded offset, following one native JMP @aa:24
/// detour (relocated routines keep their original entry as a jump).
fn resolve_call(normal: &[u8], target: u32) -> Option<usize> {
    let at = usize::try_from(target).ok()?.checked_sub(BASE_ADDRESS)?;
    match normal.get(at..at + 4)? {
        [0x5a, a, b, c] => {
            let next = u32::from_be_bytes([0, *a, *b, *c]);
            usize::try_from(next).ok()?.checked_sub(BASE_ADDRESS)
        }
        _ => Some(at),
    }
}

/// Bind the per-channel full-step offset block. Each of the two sub-blocks must
/// be followed, before any other call, by a call to a distinct coil function.
/// Returns the source word whose function receives the negative offset; a coil
/// operand exchange moves the source word and its offset to the other channel
/// together, so this element is invariant under the coil correction.
fn step_source(normal: &[u8], stored: &[&[u8]], coil: &native::PairedPhase) -> Result<u8, Unbound> {
    let plus = sites(normal, stored, STEP_PLUS);
    let minus = sites(normal, stored, STEP_MINUS);
    let ([plus], [minus]) = (plus.as_slice(), minus.as_slice()) else {
        return Err(if plus.is_empty() || minus.is_empty() {
            Unbound::Missing(Element::StepOffsets)
        } else {
            Unbound::Ambiguous(Element::StepOffsets)
        });
    };
    let callee = |site: usize| -> Option<usize> {
        let mut at = site + STEP_PLUS.len();
        let end = at + 16;
        while at < end {
            if normal.get(at) == Some(&0x5e) {
                let b = normal.get(at + 1..at + 4)?;
                return resolve_call(normal, u32::from_be_bytes([0, b[0], b[1], b[2]]));
            }
            at += 2;
        }
        None
    };
    let (Some(p), Some(m)) = (callee(*plus), callee(*minus)) else {
        return Err(Unbound::Missing(Element::StepOffsets));
    };
    // functions[0] reads source word zero, functions[1] word one.
    let word = |f: usize| coil.functions.iter().position(|start| *start == f);
    let (Some(pw), Some(mw)) = (word(p), word(m)) else {
        return Err(Unbound::Missing(Element::StepOffsets));
    };
    if pw == mw {
        return Err(Unbound::Ambiguous(Element::StepOffsets));
    }
    Ok(mw as u8)
}

// An inverted condition selects the opposite branch without moving or
// duplicating the native NEG instruction. Bind the complete prefix in either
// encoding, and report the effective mode-one sign rather than the opcode's
// presence alone.
fn mode_binding(normal: &[u8], stored: &[&[u8]]) -> Result<(u8, usize), Unbound> {
    let mut found = None;
    for (sign, template) in MODE.iter().enumerate() {
        for inverted in [false, true] {
            let mut variant = template.to_vec();
            if inverted {
                variant[6] = Some(0x47);
            }
            for at in sites(normal, stored, &variant) {
                if found.is_some() {
                    return Err(Unbound::Ambiguous(Element::ModeSign));
                }
                found = Some(((sign as u8) ^ u8::from(inverted), at));
            }
        }
    }
    found.ok_or(Unbound::Missing(Element::ModeSign))
}

/// Bind every bundle element of decoded H8 split-word Normal.
pub fn bind(normal: &[u8]) -> Result<Bundle, Unbound> {
    let Observation::Known(coil) = native::discover_pair(normal) else {
        return Err(Unbound::Missing(Element::Coil));
    };
    let Some(regions) = crate::image::regions(normal) else {
        return Err(Unbound::Missing(Element::Coil));
    };
    let stored = &regions.stored;
    let step_minus_source = step_source(normal, stored, &coil)?;
    let loader = if let Ok(program) = waveforms::loader::observe(normal) {
        program.loader
    } else {
        let mut up = sites(normal, stored, LOADER_ASCENDING);
        up.extend(sites(normal, stored, LOADER_ASCENDING_PADDED));
        let down = sites(normal, stored, LOADER_DESCENDING);
        let negated = sites(normal, stored, LOADER_NEGATED_17);
        match (up.len(), down.len(), negated.len()) {
            (1, 0, 0) => Loader::Ascending,
            // The special case must precede the ascending address computation
            // within the same loader body.
            (1, 0, 1) if negated[0] < up[0] && up[0] - negated[0] <= 0x40 => {
                Loader::AscendingNegated17
            }
            (0, 1, 0) => Loader::Descending,
            (0, 0, 0) => return Err(Unbound::Missing(Element::DspLoader)),
            _ => return Err(Unbound::Ambiguous(Element::DspLoader)),
        }
    };
    let (calibration_base, _) = one_of(normal, stored, &BASE, Element::CalibrationBase)?;
    let (calibration_offset, _) = one_of(normal, stored, &OFFSET, Element::CalibrationOffset)?;
    let (calibration_step, _) = one_of(normal, stored, &STEP, Element::CalibrationStep)?;
    let (mode_sign, _) = mode_binding(normal, stored)?;
    let (controller_mode, _) = one_of(normal, stored, &CONTROLLER, Element::ControllerMode)?;
    let table_select_0x28f = !sites(normal, stored, TABLE_SELECT).is_empty();
    Ok(Bundle {
        coil: coil.assignment,
        step_minus_source,
        loader,
        calibration_base,
        calibration_offset,
        calibration_step,
        mode_sign,
        controller_mode,
        table_select_0x28f,
    })
}

#[cfg(test)]
pub(crate) mod tests;

/// Select the source word receiving the negative full-step index offset.
///
/// Binds both complete step blocks through their calls to the paired native coil
/// functions. Only the ADD and low/high index constants change; register choices,
/// coil call addresses, waveform values and checksum bytes remain untouched.
/// The complete mechanism composer selects this source after its coil rewrite.
pub fn rewrite_step_offsets(normal: &[u8], required_source: u8) -> Result<Vec<u8>, Unbound> {
    let Observation::Known(coil) = native::discover_pair(normal) else {
        return Err(Unbound::Missing(Element::Coil));
    };
    let regions = crate::image::regions(normal).ok_or(Unbound::Missing(Element::StepOffsets))?;
    let current = step_source(normal, &regions.stored, &coil)?;
    if required_source > 1 {
        return Err(Unbound::Ambiguous(Element::StepOffsets));
    }
    let mut changed = normal.to_vec();
    if current != required_source {
        let plus = sites(normal, &regions.stored, STEP_PLUS)[0];
        let minus = sites(normal, &regions.stored, STEP_MINUS)[0];
        for (to, from) in [(plus, minus), (minus, plus)] {
            // Keep this caller's input-register move. The remainder is the
            // opposite complete OEM block already present in the same image;
            // equal block geometry preserves its relative branch destinations.
            let first = h8_asm::isa::decode_insn(
                &normal[to..],
                h8_asm::Target::H8S2000,
                h8_asm::Mode::Advanced,
            )
            .map_err(|_| Unbound::Missing(Element::StepOffsets))?;
            if first.len != 2 {
                return Err(Unbound::Missing(Element::StepOffsets));
            }
            changed[to + first.len..to + STEP_PLUS.len()]
                .copy_from_slice(&normal[from + first.len..from + STEP_PLUS.len()]);
        }
    }
    let changed_regions =
        crate::image::regions(&changed).ok_or(Unbound::Missing(Element::StepOffsets))?;
    if step_source(&changed, &changed_regions.stored, &coil)? != required_source {
        return Err(Unbound::Ambiguous(Element::StepOffsets));
    }
    Ok(changed)
}
