//! Hardware family identity: the registered-filter identity of a firmware and
//! its opaque digest. Family matching is a classification over the registered
//! owners; it lives with them, above the image primitives.
/// Typed matrix scheme used by context-aware, Envelope and receiver identities.
pub const MATRIX_FAMILY_SCHEME: &str = "pioneer.hardware.v7";

/// Opaque digest of a registered-filter identity (scheme
/// [`MATRIX_FAMILY_SCHEME`]). Matching families establish platform evidence
/// only; correction and transfer admission remain separate.
///
/// The value is an opaque hash; only equality and the hex [`Display`] form are
/// meaningful.
///
/// [`Display`]: core::fmt::Display
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Family(u64);

#[cfg(test)]
impl Family {
    pub(crate) fn from_raw(value: u64) -> Self {
        Self(value)
    }
}

impl core::fmt::Display for Family {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl core::fmt::Debug for Family {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Family({:x})", self.0)
    }
}

/// An established typed family identity: the complete registered identity,
/// whose structured-header domain keeps platforms apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// Complete version-seven identity supplied by the shared filter registry.
    Registered(crate::filters::identity::Key),
}
impl Key {
    /// Versioned binary identity; never serializes presentation text.
    pub fn canonical_bytes(&self) -> Option<alloc::vec::Vec<u8>> {
        match self {
            Self::Registered(k) => Some(k.canonical_bytes()),
        }
    }
    /// Opaque digest of the canonical identity.
    pub fn family(&self) -> Option<Family> {
        match self {
            Self::Registered(k) => Some(Family(k.fingerprint())),
        }
    }
}
/// Both established identities. Candidate equality alone does not authorize any
/// write: the necessary phase/startup corrections and receiver gates remain separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Identity without applying corrections.
    pub as_is: Key,
    /// Identity after each registered owner's explicitly supported projection.
    pub candidate: Key,
}

/// Discover typed identity using the hardware tag from structured firmware or
/// drive metadata, decoded Normal, and its exact associated Kernel when needed.
/// Does not guess a platform from a model name or substitute another Kernel.
/// ATA architecture/load base must be established by complete native consumers.
/// Unsupported tags, missing required fields and conflicting keys return None.
pub fn discover(hardware: &str, normal: &[u8], kernel: Option<&[u8]>) -> Option<Identity> {
    discover_in(&crate::filters::Context::new(crate::filters::Firmware {
        hardware,
        normal,
        kernel,
    }))
}

/// [`discover`] over an already inspected context, so one native inspection
/// can also supply the registered filter results.
pub(crate) fn discover_in(context: &crate::filters::Context<'_>) -> Option<Identity> {
    let identity = crate::filters::identity::discover(context)?;
    Some(Identity {
        as_is: Key::Registered(identity.as_is),
        candidate: Key::Registered(identity.candidate),
    })
}

/// Matrix hardware family used for matching, from structured platform metadata
/// and native code. Every required filter, including persistent layout, must be
/// known. Supply the exact associated Kernel for resident readers and V850 base
/// bindings.
///
/// The family is the registered candidate key: it is built only from facts no
/// owner corrects (each owner projects away exactly what it may correct, e.g.
/// the split-word phase assignment). Family equality never authorizes a write;
/// every remaining difference must still pass its owner's correction proofs, or
/// the pair is refused at that step. The as-is identity stays available through
/// [`discover`] for display and post-correction verification.
pub fn family_with_context(body: &[u8], hardware: &str, kernel: Option<&[u8]>) -> Option<Family> {
    discover(hardware, body, kernel)?.candidate.family()
}

#[cfg(feature = "envelope")]
impl crate::envelope::Envelope {
    /// Audited matrix family of this Normal, using its structured hardware tag.
    /// Returns None when required evidence resides in an associated Kernel;
    /// use [`Self::family_with_kernel`] for that case. Kernels have no family.
    pub fn family(&self) -> Option<Family> {
        if self.info().kind != crate::ComponentKind::Normal {
            return None;
        }
        family_with_context(&self.image, &self.info().hardware_version, None)
    }

    /// Matrix family with the exact associated Kernel. Both component kinds,
    /// hardware tags and Kernel-version tags must agree before resident evidence
    /// can participate. Header agreement alone does not prove a live capture.
    pub fn family_with_kernel(&self, kernel: &Self) -> Option<Family> {
        if self.info().kind != crate::ComponentKind::Normal
            || kernel.info().kind != crate::ComponentKind::Kernel
            || self.info().hardware_version.is_empty()
            || self.info().hardware_version != kernel.info().hardware_version
            || self.info().kernel_version.is_empty()
            || self.info().kernel_version != kernel.info().kernel_version
        {
            return None;
        }
        family_with_context(
            &self.image,
            &self.info().hardware_version,
            Some(&kernel.image),
        )
    }
}

#[cfg(feature = "envelope")]
impl crate::envelope::Update {
    /// Hardware family derived from the decoded Normal, when recognized.
    pub fn family(&self) -> Option<Family> {
        self.normal().family_with_kernel(self.kernel())
    }
}

#[cfg(all(test, feature = "envelope"))]
pub(crate) fn test_family(variant: u8) -> Family {
    let mut body = alloc::vec![0xff; 0x2000];
    crate::image::matrix::install_test_contract(&mut body, variant);
    family_with_context(&body, "SAT 8600", None).expect("registered identity")
}
