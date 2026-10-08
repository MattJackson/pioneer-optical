//! Complete component preparation. This module performs no device I/O.

use super::{builder, decode_envelope_with_kernel, header_info, DecodeError, Envelope};
use crate::{image, ComponentKind};

/// A failure while preparing an update, before any device command is issued.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateError {
    /// A component could not be loaded.
    Decode {
        /// Component being loaded.
        component: ComponentKind,
        /// Detailed envelope decoding failure.
        source: DecodeError,
    },
    /// An input carries the wrong component role.
    Role {
        /// Required component role.
        expected: ComponentKind,
        /// Role declared by the envelope.
        actual: ComponentKind,
    },
    /// A required header field is missing or differs between the components.
    Header {
        /// Header field being compared.
        field: &'static str,
        /// Value in the Kernel header.
        kernel: String,
        /// Value in the Normal header.
        normal: String,
    },
    /// The target Kernel's Normal decoding policy could not be established.
    ReceiverPolicy,
    /// A decoded image has a nonzero additive checksum or incomplete words.
    Checksum {
        /// Component whose decoded checksum failed.
        component: ComponentKind,
        /// Wrapping sum of complete big-endian words.
        sum: u32,
        /// Decoded image length, including any incomplete word.
        bytes: usize,
    },
    /// The original file could not be reproduced from its decoded representation.
    Roundtrip {
        /// Component that could not reproduce its original bytes.
        component: ComponentKind,
    },
    /// A Normal contains missing bytes that cannot be recovered from the file.
    UnrecoveredTail {
        /// First missing byte in the decoded image.
        offset: usize,
        /// Number of missing bytes.
        length: usize,
    },
    /// No implemented transfer representation exists for this component.
    Representation {
        /// Component requiring a transfer representation.
        component: ComponentKind,
        /// Detected on-disk envelope layout.
        layout: super::Layout,
    },
    /// The prepared Normal does not satisfy its target Kernel's authentication.
    Authentication,
}

impl core::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decode { component, source } => write!(f, "{component} envelope: {source}"),
            Self::Role { expected, actual } => {
                write!(f, "expected {expected} component, got {actual}")
            }
            Self::Header {
                field,
                kernel,
                normal,
            } => write!(
                f,
                "component {field} must be present and match: Kernel={kernel:?}, Normal={normal:?}"
            ),
            Self::ReceiverPolicy => {
                f.write_str("target Kernel Normal decoding policy is unsupported or ambiguous")
            }
            Self::Checksum {
                component,
                sum,
                bytes,
            } => write!(
                f,
                "{component} decoded checksum failed: sum={sum:#010x}, bytes={bytes:#x}"
            ),
            Self::Roundtrip { component } => {
                write!(f, "{component} envelope does not rebuild exactly")
            }
            Self::UnrecoveredTail { offset, length } => write!(
                f,
                "Normal has {length:#x} unrecovered bytes at decoded offset {offset:#x}"
            ),
            Self::Representation { component, layout } => write!(
                f,
                "{component} transfer representation for {layout} is not implemented"
            ),
            Self::Authentication => {
                f.write_str("prepared Normal authentication does not satisfy the target Kernel")
            }
        }
    }
}
impl std::error::Error for UpdateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A validated Kernel/Normal pair with immutable prepared component bytes.
///
/// Preparation validates the pair, not the installed drive. The receiver must
/// still establish hardware-family compatibility and its complete write plan.
#[derive(Clone, Debug)]
pub struct Update {
    kernel: Envelope,
    normal: Envelope,
    kernel_transfer: Vec<u8>,
    normal_transfer: Vec<u8>,
}

impl Update {
    /// Load and prepare a complete pair without issuing any device commands.
    pub fn load(kernel_bytes: &[u8], normal_bytes: &[u8]) -> Result<Self, UpdateError> {
        let kernel = load(kernel_bytes, ComponentKind::Kernel)?;
        let _normal = load(normal_bytes, ComponentKind::Normal)?;
        // The two loads above establish complete, typed headers.
        let kh = header_info(kernel_bytes).ok_or(UpdateError::Decode {
            component: ComponentKind::Kernel,
            source: DecodeError::InvalidHeader,
        })?;
        let nh = header_info(normal_bytes).ok_or(UpdateError::Decode {
            component: ComponentKind::Normal,
            source: DecodeError::InvalidHeader,
        })?;
        for (field, k, n) in [
            (
                "hardware version",
                &kh.hardware_version,
                &nh.hardware_version,
            ),
            ("destination", &kh.destination, &nh.destination),
            ("Kernel version", &kh.kernel_version, &nh.kernel_version),
            ("Kernel version 2", &kh.kernel_version2, &nh.kernel_version2),
        ] {
            if k.is_empty() || n.is_empty() || k != n {
                return Err(UpdateError::Header {
                    field,
                    kernel: k.clone(),
                    normal: n.clone(),
                });
            }
        }
        let normal = decode_envelope_with_kernel(normal_bytes, &kernel)
            .ok_or(UpdateError::ReceiverPolicy)?;
        if let Some(tail) = normal.unrecovered_tail() {
            return Err(UpdateError::UnrecoveredTail {
                offset: tail.start,
                length: tail.len(),
            });
        }
        for (envelope, bytes) in [(&kernel, kernel_bytes), (&normal, normal_bytes)] {
            let component = envelope.info().kind;
            let sum = envelope.image.chunks_exact(4).fold(0u32, |sum, word| {
                sum.wrapping_add(u32::from_be_bytes([word[0], word[1], word[2], word[3]]))
            });
            if envelope.image.len() % 4 != 0 || sum != 0 {
                return Err(UpdateError::Checksum {
                    component,
                    sum,
                    bytes: envelope.image.len(),
                });
            }
            if envelope.repack(&envelope.image).as_deref() != Some(bytes) {
                return Err(UpdateError::Roundtrip { component });
            }
        }
        let kernel_transfer =
            kernel
                .kernel_transfer_image()
                .ok_or(UpdateError::Representation {
                    component: ComponentKind::Kernel,
                    layout: kernel.info().layout,
                })?;
        let normal_transfer =
            normal
                .normal_transfer_image()
                .ok_or(UpdateError::Representation {
                    component: ComponentKind::Normal,
                    layout: normal.info().layout,
                })?;
        if !builder::normal_authentication_valid(&normal_transfer, &kernel.image) {
            return Err(UpdateError::Authentication);
        }
        Ok(Self {
            kernel,
            normal,
            kernel_transfer,
            normal_transfer,
        })
    }

    /// Decoded target Kernel and its envelope metadata.
    pub fn kernel(&self) -> &Envelope {
        &self.kernel
    }
    /// Normal decoded using the target Kernel's receiver policy.
    pub fn normal(&self) -> &Envelope {
        &self.normal
    }
    /// Hardware family derived from the decoded Normal, when recognized.
    pub fn family(&self) -> Option<image::Family> {
        image::family(&self.normal.image)
    }
    /// Front-key Kernel representation; receiver routing is still required.
    pub fn kernel_transfer(&self) -> &[u8] {
        &self.kernel_transfer
    }
    /// Continuous Normal representation authenticated against the target Kernel.
    pub fn normal_transfer(&self) -> &[u8] {
        &self.normal_transfer
    }
}

fn load(bytes: &[u8], expected: ComponentKind) -> Result<Envelope, UpdateError> {
    let envelope = Envelope::load(bytes).map_err(|source| UpdateError::Decode {
        component: expected,
        source,
    })?;
    let actual = envelope.info().kind;
    if actual != expected {
        return Err(UpdateError::Role { expected, actual });
    }
    Ok(envelope)
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
