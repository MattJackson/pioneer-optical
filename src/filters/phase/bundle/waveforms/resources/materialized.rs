//! Materialize a completely bound native generated waveform under exact
//! read-only calibration conditions. Only Normal-resident arithmetic whose
//! complete multiplication/division bodies are recognized is admitted.
use super::{evaluators::Calibration, generated, software, Error};
use crate::{
    filters::{phase::native, prerequisites::Word},
    image::layout::{self, H8ReaderComponent, Observation, ParameterLayout},
};
use alloc::vec::Vec;

/// One complete native generated buffer, with its exact selector predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    /// Exact native selector predicate; None is the default branch.
    pub mode: Option<u8>,
    /// Native magnitude supplied to both evaluator channels.
    pub magnitude: u16,
    /// Original producer buffer address; maps to an owned destination ROM table.
    pub source: u32,
    /// Sixty-four paired big-endian words, including native left-shift wrapping.
    pub bytes: [u8; 256],
}

/// Complete native source evidence and all conditions for its four ROM tables.
/// The operation owner must preserve every selector predicate, map all four
/// buffers to owned ROM tables, and enforce every word before transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    /// Fully bound producer, evaluator, dispatcher, selector and coil graph.
    pub source: generated::Binding,
    /// Actual Normal arithmetic bodies, including the unsigned divider core.
    pub arithmetic: native::arithmetic::Binding,
    /// Exact values returned by the native calibration getter under the guards.
    pub calibration: [i16; 8],
    /// Existing logical words required before transfer; never write effects.
    pub required_words: Vec<Word>,
    /// Four distinct native roles in selector order.
    pub tables: [Table; 4],
}

fn divide(a: i32, b: i32) -> Result<i32, Error> {
    a.checked_div(b).ok_or(Error::ResourceMismatch)
}

// This expression follows the completely matched FIRST/SECOND/SHARED native
// evaluators, including each word wrap, truncating signed division and clipping
// after the final quotient is truncated to R0. The arithmetic-body binder is a
// mandatory prerequisite; arbitrary resident ROM calls cannot use this model.
fn coefficient(raw: i16, magnitude: u16, values: &[i16]) -> Result<u16, Error> {
    if raw == 0 {
        return Ok(0);
    }
    let scaled = divide(i32::from(raw).wrapping_mul(i32::from(magnitude)), 100)?;
    let scaled = divide(scaled.wrapping_mul(768), 125)?;
    let start = if raw < 0 { 2 } else { 0 };
    let a = values[start];
    let b = values[start + 1];
    let offset = i32::from(b.wrapping_sub(a.wrapping_mul(2))).wrapping_mul(192);
    let denominator = i32::from(b.wrapping_sub(a));
    let numerator = scaled.wrapping_add(offset);
    let value = divide(
        if raw < 0 {
            numerator.wrapping_neg()
        } else {
            numerator
        },
        denominator,
    )? as i16;
    let clipped = if raw < 0 {
        value.max(-512)
    } else {
        value.min(511)
    };
    // Each native 0x1050 SHLL.W instruction shifts by TWO bits.
    Ok((clipped as u16).wrapping_shl(6))
}

/// Establish all native generated table bytes without guessing a live value.
/// For parameter-backed calibration, require each actual logical word to be
/// 0xffff: the complete getter's native erased branch then returns its bound
/// default. The source getter must be the complete recognized Normal logical
/// reader with the evaluator's exact R1 argument convention and parameter domain.
/// Constant calibration needs no live-word guard. Unknown arithmetic is refused.
pub fn prove(donor: &[u8]) -> Result<Proof, Error> {
    let source = generated::observe(donor)?;
    let arithmetic = native::arithmetic::observe(
        donor,
        0x410000,
        source.evaluator.arithmetic[0],
        source.evaluator.arithmetic[1],
    )
    .ok_or(Error::ResourceMismatch)?;
    let (calibration, required_words) = match &source.calibration.1 {
        Calibration::Constants(values) => (*values, Vec::new()),
        Calibration::Parameters {
            indices,
            defaults,
            helpers,
        } => {
            let Observation::Known(reader) = layout::discover_h8_reader(donor, None) else {
                return Err(Error::ResourceMismatch);
            };
            if reader.component != H8ReaderComponent::Normal
                || reader.getter != helpers[1]
                || reader.argument_register != 1
            {
                return Err(Error::ResourceMismatch);
            }
            let ParameterLayout::FlashRecords { domains, .. } = reader.layout else {
                return Err(Error::ResourceMismatch);
            };
            let mut words = Vec::new();
            for parameter in indices {
                if !domains
                    .iter()
                    .any(|d| d.first <= *parameter && *parameter <= d.last)
                {
                    return Err(Error::ResourceMismatch);
                }
                let word = Word {
                    parameter: *parameter,
                    value: 0xffff,
                };
                if !words.contains(&word) {
                    words.push(word);
                }
            }
            (*defaults, words)
        }
    };
    let body = &donor[source.producer.program.clone()];
    // The complete producer grammar proves these immediate magnitudes and its
    // 64-iteration paired-word write loop. Its four buffer roles were already
    // matched against every selector predicate by observe_producer.
    let magnitude_offsets = [88, 52, 76, 64];
    let mut tables = Vec::new();
    for (index, (mode, origin)) in source.consumer.choices.iter().enumerate() {
        let software::Source::Runtime(address) = origin else {
            return Err(Error::ResourceMismatch);
        };
        let offset = *magnitude_offsets
            .get(index)
            .ok_or(Error::ResourceMismatch)?;
        let magnitude = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let mut bytes = [0; 256];
        for row in 0..64 {
            for channel in 0..2 {
                let at = source.evaluator.basis.start + row * 4 + channel * 2;
                let raw = i16::from_be_bytes([donor[at], donor[at + 1]]);
                let value =
                    coefficient(raw, magnitude, &calibration[channel * 4..channel * 4 + 4])?;
                let to = row * 4 + channel * 2;
                bytes[to..to + 2].copy_from_slice(&value.to_be_bytes());
            }
        }
        tables.push(Table {
            mode: *mode,
            magnitude,
            source: *address,
            bytes,
        });
    }
    let tables = tables.try_into().map_err(|_| Error::ResourceMismatch)?;
    Ok(Proof {
        source,
        arithmetic,
        calibration,
        required_words,
        tables,
    })
}

/// Re-establish the complete native source, all guards and every emitted byte.
/// This verifies an image proof only; enforcing its live word conditions stays
/// mandatory in the complete correction operation.
pub fn verify(donor: &[u8], proof: &Proof) -> Result<(), Error> {
    if &prove(donor)? != proof {
        return Err(Error::ResourceMismatch);
    }
    Ok(())
}
