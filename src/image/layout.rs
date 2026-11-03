//! Persistent parameter formats used by the hardware compatibility filter.
//!
//! These describe traced parameter consumers, not the entire writable storage
//! device. Matching a format does not authorize a write or a format conversion.

use alloc::vec::Vec;

mod h8;
#[cfg(test)]
pub(crate) use h8::tests::{
    install as install_test_layout, install_variant as install_test_layout_variant,
};
pub(crate) use h8::{normal_reader, normal_reader_binding};
mod h8_shapes;
pub use h8::{discover_h8, discover_h8_component, discover_h8_reader};
mod relocation;
pub use relocation::{plan_h8_relocation, H8AddressEdit, H8RelocationError, H8RelocationPlan};
mod m32c;
mod m32c_serial;
mod m32c_serial_shapes;
mod m32c_shapes;
mod m7900;
mod m7900_shapes;
mod v850;
mod v850_shapes;
pub use m32c::discover_m32c_records;
pub use m32c_serial::discover_m32c_serial;
pub use m7900::{discover_m7900_ata, discover_m7900_scsi};
pub(crate) use v850::{decode_bus as decode_v850_bus, encode_bus as encode_v850_bus};
pub use v850::{discover_v850_bus, discover_v850_native};

/// An extracted value or the reason an extractor cannot establish one.
///
/// Deliberately does not implement equality: two missing observations are not
/// evidence of matching hardware. Use [`Observation::compare`] instead.
#[derive(Clone, Debug)]
pub enum Observation<T> {
    /// Native evidence establishes this value.
    Known(T),
    /// A required native path could not be established.
    Unresolved(Unresolved),
    /// Native paths establish incompatible values for the same required input.
    Conflicting,
}

impl<T: PartialEq> Observation<T> {
    /// Compare established values; unavailable or conflicting evidence is `None`.
    pub fn compare(&self, other: &Self) -> Option<bool> {
        match (self, other) {
            (Self::Known(a), Self::Known(b)) => Some(a == b),
            _ => None,
        }
    }
}

/// Why required layout evidence is unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unresolved {
    /// No complete supported native parameter reader was recognized.
    ReaderNotRecognized,
    /// Multiple reader sites were found, and their runtime selection is unproven.
    AmbiguousReader,
    /// The exact resident component containing this CPU address is unavailable.
    ResidentCodeRequired(u32),
    /// Recognized native code references bytes outside the supplied component.
    TruncatedEvidence,
}

/// Component containing a fully bound native H8 parameter reader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H8ReaderComponent {
    /// Code stored in Normal at CPU 0x410000.
    Normal,
    /// Resident code in the exact associated Kernel at CPU 0x400000.
    Kernel,
}

/// Role in the complete native parameter-reader graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H8ReaderRole {
    /// Public logical-word getter.
    Getter,
    /// Logical word to region selection.
    Resolver,
    /// Selected record and payload-word address calculation.
    Record,
    /// Payload size for the selected native region.
    RecordBytes,
    /// Total region size, including headers.
    RegionBytes,
    /// Header size derived by the native implementation.
    HeaderBytes,
    /// Header occupancy and previous-record selection.
    Scanner,
    /// Native mapped byte access, when present.
    ByteReader,
    /// Selected-bank address translation, when present.
    AddressMapper,
}

/// A complete recognized native routine, retaining its exact byte span.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H8ReaderFunction {
    /// Native purpose, independent of model name or code location.
    pub role: H8ReaderRole,
    /// CPU entry address in the containing component.
    pub address: u32,
    /// Length of the complete matched native routine.
    pub bytes: usize,
}

/// Read-side layout evidence with component ownership and bound call edges.
/// This is not a write/erase proof or authorization to relocate retained data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H8ReaderEvidence {
    /// Component owning the getter and all listed native routines.
    pub component: H8ReaderComponent,
    /// Native getter entry address.
    pub getter: u32,
    /// Word register receiving the logical parameter index, R0 or R1.
    pub argument_register: u8,
    /// Complete routines connected by the recognized native call graph.
    pub functions: Vec<H8ReaderFunction>,
    /// Primary parameter layout established by this reader.
    pub layout: ParameterLayout,
}

/// Origin against which a parameter record address is interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressBasis {
    /// An absolute CPU flash address.
    Absolute,
    /// A byte offset relative to the bank selected by native storage geometry.
    SelectedBank,
}

/// Header value tested at every two-byte record-header position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderTest {
    /// The byte at the even offset equals `0xFF`; the other byte is ignored.
    ByteFf,
    /// The whole sixteen-bit word equals `0xFFFF`.
    WordFfff,
}

/// Interpretation of parameter payload words at the native read boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordEncoding {
    /// Adjacent bytes form a little-endian sixteen-bit word.
    LittleEndian,
    /// Runtime selection between direct and address/data-permuted LE16 readers.
    DirectOrBusPermutedLittleEndian,
    /// The serial interface transfers the high byte before the low byte.
    SerialHighByteFirst,
}

/// A contiguous appended-record area in writable flash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRegion {
    /// Absolute address or selected-bank offset in bytes.
    pub address: u32,
    /// How to interpret `address`.
    pub basis: AddressBasis,
    /// Allocation size, when directly established; not inferred from used bytes.
    pub allocation_bytes: Option<u32>,
    /// Payload size of each record in bytes.
    pub record_bytes: u32,
    /// Number of record payload slots.
    pub record_count: u16,
    /// Header area size in bytes.
    pub header_bytes: u16,
    /// Test applied at successive two-byte header positions.
    pub header_test: HeaderTest,
}

impl RecordRegion {
    /// Select the native record for a supplied header.
    ///
    /// The first empty entry selects the preceding record, except that an empty
    /// first entry selects zero. A full header selects the last record. Rejects
    /// malformed geometry or truncated headers instead of guessing a record.
    pub fn selected_record(&self, header: &[u8]) -> Option<u16> {
        if self.record_count == 0
            || u32::from(self.header_bytes) != u32::from(self.record_count) * 2
            || self.record_bytes == 0
            || header.len() < usize::from(self.header_bytes)
        {
            return None;
        }
        let occupied_bytes = self
            .record_bytes
            .checked_mul(u32::from(self.record_count))?
            .checked_add(u32::from(self.header_bytes))?;
        if self
            .allocation_bytes
            .is_some_and(|size| size < occupied_bytes)
        {
            return None;
        }
        for index in 0..self.record_count {
            let at = usize::from(index) * 2;
            let empty = header[at] == 0xff
                && (self.header_test == HeaderTest::ByteFf || header[at + 1] == 0xff);
            if empty {
                return Some(index.saturating_sub(1));
            }
        }
        Some(self.record_count - 1)
    }
}

/// Traced logical word range mapped into a record region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogicalDomain {
    /// First logical parameter word, inclusive.
    pub first: u16,
    /// Last logical parameter word, inclusive.
    pub last: u16,
    /// Index of the corresponding region in the layout.
    pub region: usize,
}

/// Native persistent parameter layout, retained through phase normalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParameterLayout {
    /// Flash record regions and the logical domains established by native code.
    FlashRecords {
        /// Record formats in their native region order.
        regions: Vec<RecordRegion>,
        /// Payload encoding.
        encoding: WordEncoding,
        /// Logical mappings proven for these regions; not a whole-store schema.
        domains: Vec<LogicalDomain>,
    },
    /// Direct serial word-addressed mechanical parameter range.
    SerialRange {
        /// Number of bits encoded in the wire word address, not chip capacity.
        address_bits: u8,
        /// First serial word address.
        first_word: u16,
        /// Number of sixteen-bit words read by the native consumer.
        word_count: u16,
        /// Wire byte order.
        encoding: WordEncoding,
    },
    /// Paired serial record sets using an explicit nonsequential slot map.
    SerialSelected {
        /// Number of bits encoded in the wire word address.
        address_bits: u8,
        /// Base word address of each record set.
        bases: [u16; 2],
        /// Per-slot offsets added to each base; order is significant.
        slots: [u8; 8],
        /// Native header or fallback-word selection contract.
        selection: SerialSelection,
        /// Wire byte order.
        encoding: WordEncoding,
    },
}

/// Serial record-selection metadata, distinct from the payload slot map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SerialSelection {
    /// A single header word consumed by the selector.
    Header(u16),
    /// Ordered words used by conditional fallback selection.
    FallbackWords([u16; 8]),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(test: HeaderTest) -> RecordRegion {
        RecordRegion {
            address: 0x7f0000,
            basis: AddressBasis::Absolute,
            allocation_bytes: None,
            record_bytes: 320,
            record_count: 40,
            header_bytes: 80,
            header_test: test,
        }
    }

    #[test]
    fn unknown_and_conflicting_evidence_never_match() {
        let missing = Observation::<RecordRegion>::Unresolved(Unresolved::ReaderNotRecognized);
        let conflict = Observation::<RecordRegion>::Conflicting;
        let known = Observation::Known(region(HeaderTest::ByteFf));
        assert_eq!(missing.compare(&missing), None);
        assert_eq!(conflict.compare(&conflict), None);
        assert_eq!(known.compare(&missing), None);
        assert_eq!(missing.compare(&known), None);
        assert_eq!(known.compare(&known), Some(true));
    }

    #[test]
    fn sat8000_and_banked_records_are_not_interchangeable() {
        let absolute = region(HeaderTest::ByteFf);
        let banked = RecordRegion {
            address: 0x9984,
            basis: AddressBasis::SelectedBank,
            record_count: 20,
            header_bytes: 40,
            ..absolute.clone()
        };
        assert_eq!(
            Observation::Known(absolute).compare(&Observation::Known(banked)),
            Some(false)
        );
    }

    #[test]
    fn partial_ffff_header_word_distinguishes_native_formats() {
        let mut header = [0; 80];
        header[4] = 0xff;
        assert_eq!(region(HeaderTest::ByteFf).selected_record(&header), Some(1));
        assert_eq!(
            region(HeaderTest::WordFfff).selected_record(&header),
            Some(39)
        );
        header[5] = 0xff;
        assert_eq!(
            region(HeaderTest::WordFfff).selected_record(&header),
            Some(1)
        );
    }

    #[test]
    fn every_header_position_including_empty_and_full() {
        for test in [HeaderTest::ByteFf, HeaderTest::WordFfff] {
            let region = region(test);
            for first_empty in 0..=40 {
                let mut header = [0xff; 80];
                header[..first_empty * 2].fill(0);
                assert_eq!(
                    region.selected_record(&header),
                    Some(first_empty.saturating_sub(1) as u16)
                );
            }
            assert_eq!(region.selected_record(&[0xff; 79]), None);
        }
    }

    #[test]
    fn malformed_geometry_cannot_select_a_record() {
        let mut r = region(HeaderTest::ByteFf);
        r.header_bytes = 40;
        assert_eq!(r.selected_record(&[0; 80]), None);
        r.header_bytes = 80;
        r.allocation_bytes = Some(12879);
        assert_eq!(r.selected_record(&[0; 80]), None);
        r.allocation_bytes = Some(12880);
        assert_eq!(r.selected_record(&[0; 80]), Some(39));
        r.record_bytes = u32::MAX;
        assert_eq!(r.selected_record(&[0; 80]), None);
    }
}
