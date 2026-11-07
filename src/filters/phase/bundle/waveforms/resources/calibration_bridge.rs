//! Transfer a native, image-resident calibration getter at its existing entry.
//! This stage establishes calibration returns only. The mechanism owner must
//! separately establish evaluator arithmetic and selector/basis equivalence.
use super::{evaluators, Error};
use crate::{
    filters::prerequisites::Word,
    image::layout::{self, H8ReaderComponent, Observation, ParameterLayout},
};
use alloc::vec::Vec;

/// Image-side calibration adaptation and its mandatory read-only conditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Target image with its existing getter adapted, if necessary.
    pub image: Vec<u8>,
    /// Exact existing words the complete operation must check before transfer.
    /// An empty list denotes an unconditional image-side adaptation.
    pub required_words: Vec<Word>,
}

/// Plan a native source adaptation, retaining any exact live-word conditions.
/// A parameter-backed donor can match a constant target only when its complete
/// native reader graph establishes the same logical-word read used by the live
/// prerequisite executor. Neither helper addresses nor erased defaults alone
/// establish that relationship. The target's fixed values remain unchanged.
pub fn plan(target: &[u8], donor: &[u8]) -> Result<Plan, Error> {
    let before = evaluators::observe(target)?;
    let source = evaluators::observe(donor)?;
    let (_, current) = evaluators::calibration(target, &before)?;
    let (_, required) = evaluators::calibration(donor, &source)?;
    if let (
        evaluators::Calibration::Constants(values),
        evaluators::Calibration::Parameters {
            indices,
            defaults,
            helpers,
        },
    ) = (&current, &required)
    {
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
        let mut required_words = Vec::new();
        for (mode, (&parameter, &value)) in indices.iter().zip(values).enumerate() {
            if !domains
                .iter()
                .any(|domain| domain.first <= parameter && parameter <= domain.last)
                || (value == -1 && defaults[mode] != -1)
            {
                return Err(Error::ResourceMismatch);
            }
            let word = Word {
                parameter,
                value: value as u16,
            };
            if required_words
                .iter()
                .any(|old: &Word| old.parameter == word.parameter && old.value != word.value)
            {
                return Err(Error::ResourceMismatch);
            }
            if !required_words.contains(&word) {
                required_words.push(word);
            }
        }
        return Ok(Plan {
            image: target.to_vec(),
            required_words,
        });
    }
    Ok(Plan {
        image: copy_getter(target, donor)?,
        required_words: Vec::new(),
    })
}

/// Copy the donor's complete fixed-value getter into the target's bound getter.
///
/// The constant OEM program has only relative internal branches and register
/// operations, so moving its complete bytes preserves all eight return values
/// without retargeting calls or accessing persistent storage. The target entry,
/// evaluator programs, and arithmetic helpers remain unchanged. Unused bytes
/// after a shrinking getter are retained, not allocated to another routine.
///
/// Parameter-backed donors require identical source contracts. In particular,
/// their context/getter addresses are not transferable service ABIs and their
/// erased-word defaults cannot be substituted for actual stored calibration.
pub fn transplant(target: &[u8], donor: &[u8]) -> Result<Vec<u8>, Error> {
    let plan = plan(target, donor)?;
    if !plan.required_words.is_empty() {
        return Err(Error::ResourceMismatch);
    }
    Ok(plan.image)
}

fn copy_getter(target: &[u8], donor: &[u8]) -> Result<Vec<u8>, Error> {
    let before = evaluators::observe(target)?;
    let source = evaluators::observe(donor)?;
    let (destination, current) = evaluators::calibration(target, &before)?;
    let (origin, required) = evaluators::calibration(donor, &source)?;
    if current == required {
        return Ok(target.to_vec());
    }
    // The complete parameter grammar already binds each branch and fallback.
    // Preserve target helper calls and its self-call relocation; only transfer
    // the donor's logical word indices and erased-word fallback immediates.
    if let (
        evaluators::Calibration::Parameters {
            helpers: current_helpers,
            ..
        },
        evaluators::Calibration::Parameters {
            indices,
            defaults,
            helpers,
        },
    ) = (&current, &required)
    {
        if current_helpers != helpers {
            return Err(Error::ResourceMismatch);
        }
        let mut changed = target.to_vec();
        for (offset, value) in [246, 220, 194, 168, 140, 110, 80, 50]
            .into_iter()
            .zip(indices.iter().copied())
            .chain(
                [262, 236, 210, 184, 158, 128, 98, 68]
                    .into_iter()
                    .zip(defaults.iter().map(|v| *v as u16)),
            )
        {
            let at = destination.start + offset;
            changed[at..at + 2].copy_from_slice(&value.to_be_bytes());
        }
        if evaluators::observe(&changed)? != before
            || evaluators::calibration(&changed, &before)?.1 != required
        {
            return Err(Error::ResourceMismatch);
        }
        return Ok(changed);
    }
    if !matches!(required, evaluators::Calibration::Constants(_))
        || origin.len() > destination.len()
        || before
            .programs
            .iter()
            .chain([&before.basis])
            .any(|span| span.start < destination.end && destination.start < span.end)
    {
        return Err(Error::ResourceMismatch);
    }
    let mut changed = target.to_vec();
    changed[destination.start..destination.start + origin.len()].copy_from_slice(&donor[origin]);
    if evaluators::observe(&changed)? != before
        || evaluators::calibration(&changed, &before)?.1 != required
    {
        return Err(Error::ResourceMismatch);
    }
    Ok(changed)
}

/// Rebind the resulting source and check the exact native getter bytes. Other
/// disjoint mechanism changes may coexist; none may alter the calibration body.
pub fn verify(target: &[u8], donor: &[u8], changed: &[u8]) -> Result<(), Error> {
    if !verify_guarded(target, donor, changed)?.is_empty() {
        return Err(Error::ResourceMismatch);
    }
    Ok(())
}

/// Verify a conditional image adaptation and return its mandatory word checks.
/// The caller must retain and enforce every returned condition; this function
/// checks image bytes and native read authority, not the live device values.
pub fn verify_guarded(target: &[u8], donor: &[u8], changed: &[u8]) -> Result<Vec<Word>, Error> {
    let expected = plan(target, donor)?;
    let before = evaluators::observe(target)?;
    let wanted = evaluators::calibration(&expected.image, &before)?;
    let actual = evaluators::calibration(changed, &evaluators::observe(changed)?)?;
    if actual != wanted || changed.get(wanted.0.clone()) != expected.image.get(wanted.0) {
        return Err(Error::ResourceMismatch);
    }
    Ok(expected.required_words)
}
