//! Read-only, single-envelope decomposition and analysis.
//!
//! Pairwise comparison belongs to consumers of these facts. Unrecognized data is
//! retained, never silently discarded or interpreted as executable code.

mod metadata;
mod references;
mod runtime;
mod tables;
pub use references::Reference;
pub use tables::{Record, Table};

use crate::envelope::{self, Envelope};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::ops::Range;

/// Limits for analysis of one envelope.
#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Maximum total expanded stream bytes per component.
    pub expanded_bytes: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            expanded_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Stage notification. Returning false requests cooperative cancellation.
pub trait Observer {
    /// Called between bounded units of work.
    fn proceed(&mut self, stage: &'static str, done: usize, total: usize) -> bool;
}
impl Observer for () {
    fn proceed(&mut self, _: &'static str, _: usize, _: usize) -> bool {
        true
    }
}

/// Fatal analysis failure. Unsupported structure is a diagnostic instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The caller cancelled the operation.
    Cancelled,
    /// A configured resource limit would be exceeded.
    ResourceLimit,
}
impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::Cancelled => "pioneer.analysis.cancelled",
            Self::ResourceLimit => "pioneer.analysis.resource_limit",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "Firmware analysis cancelled",
            Self::ResourceLimit => "Firmware analysis exceeds the configured resource limit",
        })
    }
}
impl std::error::Error for Error {}

/// A nonfatal limitation, retained in reports and exports.
#[derive(Clone, Debug, Serialize)]
pub struct Diagnostic {
    /// Stable language-independent diagnostic identifier.
    pub code: &'static str,
    /// English explanation; clients may translate using the code.
    pub message: String,
}

/// Facts about one decoded firmware component.
#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    /// Hardware family derived by the existing image classifier, if available.
    pub family: Option<String>,
    /// Family derivation namespace; values from other schemes are not comparable.
    pub family_scheme: &'static str,
    /// Envelope model label, not a hardware-family identifier.
    pub model: String,
    /// Component role from the envelope.
    pub component: String,
    /// Revision label.
    pub revision: String,
    /// Hardware/SAT label, distinct from family.
    pub hardware: String,
    /// Detected envelope codec.
    pub codec: String,
    /// Decoded content hash.
    pub sha256: String,
    /// Decoded content length.
    pub size: usize,
    /// UHD marker detected by the existing image classifier; None for non-Normal components.
    pub uhd: Option<bool>,
    /// Encoding seed where recoverable.
    pub encoding_seed: Option<u32>,
}

/// One disjoint decoded-body extent or one expanded COMP stream.
#[derive(Clone, Debug, Serialize)]
pub struct Region<'a> {
    /// Stable index in this component's region list.
    pub id: usize,
    /// Human-readable structural name, without inferred proprietary semantics.
    pub name: String,
    /// Enclosing stored range in the decoded component (not the envelope file).
    pub stored: Range<usize>,
    /// Runtime base when established by a recognized component layout.
    pub address: Option<u32>,
    /// Loader instruction extent supporting a derived runtime address, when applicable.
    pub address_source: Option<Range<usize>>,
    /// Recognized descriptive or validated derived fields, in region coordinates.
    pub metadata: Vec<Range<usize>>,
    /// Directory stream number; None for uncompressed body extents.
    pub stream: Option<usize>,
    /// SHA-256 of logical (expanded, when applicable) bytes.
    pub sha256: String,
    /// Number of logical bytes.
    pub size: usize,
    /// Structurally identified tables; unknown field semantics stay explicit.
    pub tables: Vec<Table>,
    /// Direct instruction references established from this image alone.
    pub references: Vec<Reference>,
    #[serde(skip)]
    bytes: Cow<'a, [u8]>,
}
impl Region<'_> {
    /// Logical bytes. Offsets within these bytes are not compressed-file offsets.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn into_owned(self) -> Region<'static> {
        Region {
            id: self.id,
            name: self.name,
            stored: self.stored,
            address: self.address,
            address_source: self.address_source,
            metadata: self.metadata,
            stream: self.stream,
            sha256: self.sha256,
            size: self.size,
            tables: self.tables,
            references: self.references,
            bytes: Cow::Owned(self.bytes.into_owned()),
        }
    }
}

/// Reusable single-component analysis. Inspect and Compare consume the same view.
#[derive(Clone, Debug, Serialize)]
pub struct FirmwareAnalysis<'a> {
    /// Hardware family and source facts.
    pub identity: Identity,
    /// Disjoint logical regions, covering all decoded storage.
    pub regions: Vec<Region<'a>>,
    /// Known limits of this analysis.
    pub diagnostics: Vec<Diagnostic>,
}
impl FirmwareAnalysis<'_> {
    /// Retain an analysis independently of its decoded envelope.
    pub fn into_owned(self) -> FirmwareAnalysis<'static> {
        FirmwareAnalysis {
            identity: self.identity,
            regions: self.regions.into_iter().map(Region::into_owned).collect(),
            diagnostics: self.diagnostics,
        }
    }
}

pub(super) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn check(
    observer: &mut dyn Observer,
    stage: &'static str,
    done: usize,
    total: usize,
) -> Result<(), Error> {
    if observer.proceed(stage, done, total) {
        Ok(())
    } else {
        Err(Error::Cancelled)
    }
}

impl Envelope {
    /// Inspect decoded firmware using the shared codec and COMP parser.
    /// No device operations or firmware modifications are performed.
    pub fn analyze(
        &self,
        options: Options,
        observer: &mut dyn Observer,
    ) -> Result<FirmwareAnalysis<'_>, Error> {
        check(observer, "Inspecting firmware", 0, self.image.len())?;
        let info = self.info();
        let mut result = FirmwareAnalysis {
            identity: Identity {
                family: None,
                family_scheme: "pioneer.hardware.v1",
                model: info.model.clone(),
                component: info.kind.to_string(),
                revision: info.revision.clone(),
                hardware: info.hardware_version.clone(),
                codec: info.layout.as_str().into(),
                sha256: hash(&self.image),
                size: self.image.len(),
                uhd: (info.kind == crate::ComponentKind::Normal).then(|| self.is_uhd()),
                encoding_seed: self.encoding_seed(),
            },
            regions: Vec::new(),
            diagnostics: Vec::new(),
        };
        if self.unrecovered_tail().is_some() {
            result.diagnostics.push(Diagnostic {
                code: "pioneer.analysis.unrecovered_tail",
                message: "Some decoded bytes could not be recovered; this component is incomplete."
                    .into(),
            });
        }
        let streams = match envelope::inspect_streams(
            &self.image,
            options.expanded_bytes,
            &mut || observer.proceed("Expanding streams", 0, self.image.len()),
        ) {
            Ok(streams) => streams,
            Err(envelope::StreamError::Limit) => return Err(Error::ResourceLimit),
            Err(envelope::StreamError::Cancelled) => return Err(Error::Cancelled),
            Err(error) => {
                let code = match error {
                    envelope::StreamError::Directory => "pioneer.analysis.invalid_directory",
                    envelope::StreamError::Ambiguous => "pioneer.analysis.ambiguous_comp",
                    _ => "pioneer.analysis.invalid_comp",
                };
                result.diagnostics.push(Diagnostic { code, message: "COMP data could not be resolved uniquely and completely. Stored bytes remain available; streams were not interpreted.".into() });
                None
            }
        };
        // Match the established family API's fallback when streams are unavailable.
        // Stream diagnostics still prevent claiming complete decomposition.
        if streams.is_none() {
            result.identity.family =
                crate::image::family_parts(&self.image, &self.image).map(|f| f.to_string());
        }
        let body_base = streams.as_ref().map(|(base, _)| *base).or_else(|| {
            (info.kind == crate::ComponentKind::Kernel
                && self.image.len() == crate::image::KERNEL_LEN)
                .then_some(crate::image::KERNEL_BASE)
        });
        let mut cursor = 0;
        if let Some((_, mut streams)) = streams {
            let first = streams
                .iter()
                .map(|s| s.info.image_offset)
                .min()
                .unwrap_or(0);
            let head = &self.image[..first];
            let mut family_code = head.to_vec();
            // Reuse the existing family algorithm's input convention. This is
            // not a semantic classification of arbitrary stream number five.
            if let Some(stream) = streams.get(5) {
                family_code.extend_from_slice(&stream.expanded);
            }
            result.identity.family =
                crate::image::family_parts(&family_code, head).map(|f| f.to_string());
            let total = streams
                .iter()
                .try_fold(0usize, |n, s| n.checked_add(s.expanded.len()))
                .ok_or(Error::ResourceLimit)?;
            if total > options.expanded_bytes {
                return Err(Error::ResourceLimit);
            }
            let mut indexed: Vec<_> = streams.drain(..).enumerate().collect();
            indexed.sort_by_key(|(_, s)| s.info.image_offset);
            let valid = indexed
                .iter()
                .try_fold(0usize, |previous, (_, s)| {
                    let start = s.info.image_offset;
                    let end = start.checked_add(4)?.checked_add(s.info.compressed_size)?;
                    (start >= previous && end <= self.image.len()).then_some(end)
                })
                .is_some();
            if valid {
                for (index, stream) in indexed {
                    check(observer, "Inspecting streams", index, total)?;
                    let start = stream.info.image_offset;
                    if start > cursor {
                        result.push_region(
                            cursor..start,
                            None,
                            Cow::Borrowed(&self.image[cursor..start]),
                        );
                    }
                    cursor = start + 4 + stream.info.compressed_size;
                    result.push_region(start..cursor, Some(index), Cow::Owned(stream.expanded));
                }
            } else {
                result.diagnostics.push(Diagnostic { code: "pioneer.analysis.overlapping_streams", message: "COMP storage overlaps; retaining the original body without interpreting streams.".into() });
            }
        }
        if cursor < self.image.len() {
            result.push_region(
                cursor..self.image.len(),
                None,
                Cow::Borrowed(&self.image[cursor..]),
            );
        }
        for region in &mut result.regions {
            if region.stream.is_none() {
                region.address =
                    body_base.and_then(|base| base.checked_add(region.stored.start as u32));
            }
        }
        if let Some(base) = body_base {
            runtime::identify(&self.image, base, &mut result.regions);
        }
        metadata::identify(self, &mut result.regions);
        if matches!(
            info.layout,
            envelope::Layout::Normal
                | envelope::Layout::NormalReverse
                | envelope::Layout::NormalScaledKey
                | envelope::Layout::KernelFront
                | envelope::Layout::KernelDerived
        ) {
            references::identify(&mut result);
        }
        result.diagnostics.push(Diagnostic { code: "pioneer.analysis.semantic_coverage", message: "Unrecognized data and table fields are retained as bytes. String-table recognition does not establish write-strategy field meanings.".into() });
        check(
            observer,
            "Inspection complete",
            self.image.len(),
            self.image.len(),
        )?;
        Ok(result)
    }
}
impl<'a> FirmwareAnalysis<'a> {
    fn push_region(&mut self, stored: Range<usize>, stream: Option<usize>, bytes: Cow<'a, [u8]>) {
        self.regions.push(Region {
            id: self.regions.len(),
            name: stream.map_or_else(
                || format!("Body at {:#x}", stored.start),
                |i| format!("COMP stream {i}"),
            ),
            stored,
            address: None,
            address_source: None,
            metadata: Vec::new(),
            stream,
            sha256: hash(&bytes),
            size: bytes.len(),
            tables: tables::inspect(&bytes),
            references: Vec::new(),
            bytes,
        });
    }
}

#[cfg(test)]
mod runtime_tests;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
