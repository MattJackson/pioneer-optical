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
    generated: bool,
    generated_words: Vec<Word>,
    sat1_kernel: Option<Vec<u8>>,
    cross: Option<bundle::waveforms::resources::cross_representation::Plan>,
    pointer: Option<bundle::waveforms::resources::pointer_composition::Plan>,
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
        let (image, specialized) = match direct {
            Ok(image) => (image, false),
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
                (image, true)
            }
        };
        Ok(Self {
            donor,
            image,
            selection_required,
            specialized,
            generated: false,
            generated_words: Vec::new(),
            sat1_kernel: None,
            cross: None,
            pointer: None,
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
            generated: false,
            generated_words: Vec::new(),
            sat1_kernel: None,
            cross: Some(cross),
            pointer: None,
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
            generated: false,
            generated_words: Vec::new(),
            sat1_kernel: None,
            cross: None,
            pointer: Some(pointer),
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
            generated: true,
            generated_words: plan.required_words,
            sat1_kernel: None,
            cross: None,
            pointer: None,
        })
    }
    pub(super) fn plan_sat1(transition: &Transition<'_, '_>) -> Result<Self, Error> {
        let target_kernel = transition
            .target
            .firmware
            .kernel
            .ok_or(Error::Unsupported)?;
        let donor_kernel = transition
            .installed
            .firmware
            .kernel
            .ok_or(Error::Unsupported)?;
        let donor = transition.installed.firmware.normal.to_vec();
        let image = super::native::sat1::transplant(
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
            generated: false,
            generated_words: Vec::new(),
            sat1_kernel: Some(donor_kernel.to_vec()),
            cross: None,
            pointer: None,
        })
    }
    pub(super) fn required_words(&self) -> Vec<Word> {
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
        if let Some(donor_kernel) = &self.sat1_kernel {
            return super::native::sat1::verify(
                context.target.normal,
                context.target.kernel.ok_or(Error::VerificationFailed)?,
                &self.donor,
                donor_kernel,
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
