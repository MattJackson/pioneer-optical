//! Full OEM mechanism effects owned by the phase filter.
use super::{bundle, Error, Preparation, Transition};
use crate::filters::prerequisites::Word;
use alloc::{vec, vec::Vec};

#[derive(Debug)]
pub(super) struct Mechanism {
    donor: Vec<u8>,
    image: Vec<u8>,
    selection_required: bool,
    specialized: bool,
    reader_retired: bool,
    generated: bool,
    generated_words: Vec<Word>,
    sat1: bool,
    sat1_kernel: Option<Vec<u8>>,
    cross: Option<bundle::waveforms::resources::cross_representation::Plan>,
    pointer: Option<bundle::waveforms::resources::pointer_composition::Plan>,
    reverse: Option<bundle::waveforms::resources::reverse_composition::Plan>,
}
impl Mechanism {
    pub(super) fn plan(
        transition: &Transition<'_, '_>,
        selection_required: bool,
    ) -> Result<Self, Error> {
        let donor = transition.installed.firmware.normal.to_vec();
        // Prefer in-place native specialization. Growth may use only a bound
        // replaced loader suffix with exact resident-component reference proof.
        let direct = bundle::composition::transplant(
            transition.target.firmware.normal,
            &donor,
            bundle::composition::Space::default(),
            None,
        );
        let direct = direct.map(|image| (image, false)).or_else(|error| {
            transition
                .target
                .firmware
                .kernel
                .and_then(|kernel| {
                    bundle::composition::transplant_reusing_reader_with_kernel(
                        transition.target.firmware.normal,
                        &donor,
                        kernel,
                    )
                    .ok()
                })
                .map(|image| (image, true))
                .ok_or(error)
        });
        let (image, specialized, reader_retired) = match direct {
            Ok((image, reader_retired)) => (image, false, reader_retired),
            Err(_) => {
                let image = bundle::composition::transplant_specialized_with_kernel(
                    transition.target.firmware.normal,
                    &donor,
                    transition.target.firmware.kernel,
                )
                .or_else(|_| {
                    let kernel = transition
                        .target
                        .firmware
                        .kernel
                        .ok_or(bundle::composition::Error::ComponentOwnership)?;
                    bundle::composition::transplant_reusing_loader(
                        transition.target.firmware.normal,
                        &donor,
                        kernel,
                    )
                });
                let image = match image {
                    Ok(image) => image,
                    Err(_) => return Self::plan_cross(transition),
                };
                (image, true, false)
            }
        };
        Ok(Self {
            donor,
            image,
            selection_required,
            specialized,
            reader_retired,
            generated: false,
            generated_words: Vec::new(),
            sat1: false,
            sat1_kernel: None,
            cross: None,
            pointer: None,
            reverse: None,
        })
    }
    fn plan_cross(transition: &Transition<'_, '_>) -> Result<Self, Error> {
        let target = transition.target.firmware;
        let source = transition.installed.firmware;
        let cross = match bundle::waveforms::resources::cross_representation::plan(
            target.normal,
            source.normal,
            target.kernel.ok_or(Error::Unsupported)?,
            source.kernel.ok_or(Error::Unsupported)?,
        ) {
            Ok(plan) => plan,
            Err(_) => return Self::plan_pointer(transition),
        };
        Ok(Self {
            donor: source.normal.to_vec(),
            image: cross.image().to_vec(),
            selection_required: false,
            specialized: false,
            reader_retired: false,
            generated: false,
            generated_words: Vec::new(),
            sat1: false,
            sat1_kernel: None,
            cross: Some(cross),
            pointer: None,
            reverse: None,
        })
    }
    fn plan_pointer(transition: &Transition<'_, '_>) -> Result<Self, Error> {
        let target = transition.target.firmware;
        let source = transition.installed.firmware;
        let pointer = bundle::waveforms::resources::pointer_composition::plan(
            target.normal,
            source.normal,
            target.kernel.ok_or(Error::Unsupported)?,
            source.kernel.ok_or(Error::Unsupported)?,
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            donor: source.normal.to_vec(),
            image: pointer.image().to_vec(),
            selection_required: false,
            specialized: false,
            reader_retired: false,
            generated: false,
            generated_words: Vec::new(),
            sat1: false,
            sat1_kernel: None,
            cross: None,
            pointer: Some(pointer),
            reverse: None,
        })
    }
    pub(super) fn plan_reverse(transition: &Transition<'_, '_>) -> Result<Self, Error> {
        let target = transition.target.firmware;
        let source = transition.installed.firmware;
        let reverse = bundle::waveforms::resources::reverse_composition::plan(
            target.normal,
            source.normal,
            target.kernel.ok_or(Error::Unsupported)?,
            source.kernel.ok_or(Error::Unsupported)?,
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            donor: source.normal.to_vec(),
            image: reverse.image().to_vec(),
            selection_required: false,
            specialized: false,
            reader_retired: false,
            generated: false,
            generated_words: Vec::new(),
            sat1: false,
            sat1_kernel: None,
            cross: None,
            pointer: None,
            reverse: Some(reverse),
        })
    }
    pub(super) fn plan_generated(transition: &Transition<'_, '_>) -> Result<Self, Error> {
        let donor = transition.installed.firmware.normal.to_vec();
        let plan = bundle::waveforms::resources::generated::plan_with_kernel(
            transition.target.firmware.normal,
            &donor,
            transition.target.firmware.kernel,
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            donor,
            image: plan.image,
            selection_required: false,
            specialized: false,
            reader_retired: false,
            generated: true,
            generated_words: plan.required_words,
            sat1: false,
            sat1_kernel: None,
            cross: None,
            pointer: None,
            reverse: None,
        })
    }
    pub(super) fn plan_sat1(transition: &Transition<'_, '_>) -> Result<Self, Error> {
        let target_kernel = transition.target.firmware.kernel;
        let donor_kernel = transition.installed.firmware.kernel;
        let donor = transition.installed.firmware.normal.to_vec();
        let image = super::native::sat1::transplant_optional(
            transition.target.firmware.normal,
            target_kernel,
            &donor,
            donor_kernel,
        )
        .map_err(|_| Error::Unsupported)?;
        Ok(Self {
            donor,
            image,
            selection_required: false,
            specialized: false,
            reader_retired: false,
            generated: false,
            generated_words: Vec::new(),
            sat1: true,
            sat1_kernel: donor_kernel.map(<[u8]>::to_vec),
            cross: None,
            pointer: None,
            reverse: None,
        })
    }
    pub(super) fn required_words(&self) -> Vec<Word> {
        if let Some(reverse) = &self.reverse {
            return reverse.required_words().to_vec();
        }
        if let Some(pointer) = &self.pointer {
            return pointer.required_words().to_vec();
        }
        if self.generated {
            return self.generated_words.clone();
        }
        if self.selection_required {
            vec![Word {
                parameter: 0x28f,
                value: 1,
            }]
        } else {
            Vec::new()
        }
    }
    pub(super) fn prepare(&self, context: &Preparation<'_>) -> Result<Vec<u8>, Error> {
        #[cfg(feature = "envelope")]
        if let Some(normal) = context.normal {
            use crate::envelope::Layout;
            if !matches!(
                normal.info().layout,
                Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
            ) {
                return Err(Error::Unsupported);
            }
            normal
                .repair_image_checksum(&self.image)
                .ok_or(Error::Representation)?;
        }
        self.verify(context, &self.image)?;
        Ok(self.image.clone())
    }
    pub(super) fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        if normal.len() != self.image.len() {
            return Err(Error::VerificationFailed);
        }
        // Other filter owners may add disjoint effects; every byte this owner
        // changes must survive, apart from the shared checksum field.
        for (at, ((before, expected), actual)) in context
            .target
            .normal
            .iter()
            .zip(&self.image)
            .zip(normal)
            .enumerate()
        {
            if !(16..20).contains(&at) && before != expected && actual != expected {
                return Err(Error::VerificationFailed);
            }
        }
        if let Some(reverse) = &self.reverse {
            return reverse
                .verify(
                    context.target.normal,
                    context.target.kernel.ok_or(Error::VerificationFailed)?,
                    normal,
                )
                .map_err(|_| Error::VerificationFailed);
        }
        if let Some(pointer) = &self.pointer {
            return pointer
                .verify(
                    context.target.normal,
                    context.target.kernel.ok_or(Error::VerificationFailed)?,
                    normal,
                )
                .map_err(|_| Error::VerificationFailed);
        }
        if let Some(cross) = &self.cross {
            return cross
                .verify(
                    context.target.normal,
                    context.target.kernel.ok_or(Error::VerificationFailed)?,
                    normal,
                )
                .map_err(|_| Error::VerificationFailed);
        }
        if self.sat1 {
            return super::native::sat1::verify_optional(
                context.target.normal,
                context.target.kernel,
                &self.donor,
                self.sat1_kernel.as_deref(),
                normal,
            )
            .map_err(|_| Error::VerificationFailed);
        }
        if self.generated {
            return bundle::waveforms::resources::generated::verify_with_kernel(
                context.target.normal,
                &self.donor,
                normal,
                context.target.kernel,
            )
            .map_err(|_| Error::VerificationFailed);
        }
        bundle::composition::verify_program_bytes(&self.image, normal)
            .map_err(|_| Error::VerificationFailed)?;
        if self.reader_retired {
            bundle::composition::verify_reader_retirement(
                context.target.normal,
                context.target.kernel.ok_or(Error::VerificationFailed)?,
                normal,
            )
            .map_err(|_| Error::VerificationFailed)?;
        }
        bundle::composition::verify_effective_result(
            context.target.normal,
            &self.donor,
            normal,
            self.specialized,
            context.target.kernel,
        )
        .map_err(|_| Error::VerificationFailed)
    }
}
