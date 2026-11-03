//! Version 6 canonical binary identity. All integers are unsigned big endian;
//! vectors use u32 element counts, enums have explicit u8 tags, and options
//! have a u8 presence tag. Field order is fixed here, never Debug/display text.
use super::{AtaInput, AtaKey, SatKey};
use crate::image::{geometry, inputs, irq, layout::*, peripheral, phase::Assignment, Family};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
struct Encoder(Vec<u8>);
impl Encoder {
    fn new() -> Self {
        Self(b"PIONEER-FAMILY\0\x06".to_vec())
    }
    fn byte(&mut self, v: u8) {
        self.0.push(v);
    }
    fn word(&mut self, v: u16) {
        self.0.extend(v.to_be_bytes());
    }
    fn long(&mut self, v: u32) {
        self.0.extend(v.to_be_bytes());
    }
    fn count(&mut self, v: usize) -> Option<()> {
        self.long(v.try_into().ok()?);
        Some(())
    }
    fn assignment(&mut self, v: Option<Assignment>) {
        self.byte(match v {
            None => 0,
            Some(Assignment::Direct) => 1,
            Some(Assignment::Swapped) => 2,
        });
    }
    fn geometry(&mut self, g: &geometry::Geometry) {
        match g {
            geometry::Geometry::MarkerBanks { marker, stride } => {
                self.byte(1);
                self.long(*marker);
                self.long(*stride);
            }
            geometry::Geometry::NativeBanks { bases, stride } => {
                self.byte(2);
                for a in bases {
                    self.long(*a);
                }
                self.long(*stride);
            }
        }
    }
    fn irq(&mut self, v: &irq::Value) {
        match v {
            irq::Value::Controller { and_mask, or_mask } => {
                self.byte(1);
                self.byte(*and_mask);
                self.byte(*or_mask);
            }
            irq::Value::Input(t) => {
                self.byte(2);
                self.byte(match t.encoding {
                    inputs::Encoding::Absolute16 => 1,
                    inputs::Encoding::Absolute32 => 2,
                });
                self.long(t.address);
                self.byte(t.bit);
                self.byte(u8::from(t.active));
            }
            irq::Value::TrayCloseRoute => self.byte(3),
        }
    }
    fn encoding(&mut self, v: WordEncoding) {
        self.byte(match v {
            WordEncoding::LittleEndian => 1,
            WordEncoding::DirectOrBusPermutedLittleEndian => 2,
            WordEncoding::SerialHighByteFirst => 3,
        });
    }
    fn layout(&mut self, v: &ParameterLayout) -> Option<()> {
        match v {
            ParameterLayout::FlashRecords {
                regions,
                encoding,
                domains,
            } => {
                self.byte(1);
                self.encoding(*encoding);
                self.count(regions.len())?;
                for r in regions {
                    self.long(r.address);
                    self.byte(match r.basis {
                        AddressBasis::Absolute => 1,
                        AddressBasis::SelectedBank => 2,
                    });
                    self.byte(u8::from(r.allocation_bytes.is_some()));
                    if let Some(n) = r.allocation_bytes {
                        self.long(n);
                    }
                    self.long(r.record_bytes);
                    self.word(r.record_count);
                    self.word(r.header_bytes);
                    self.byte(match r.header_test {
                        HeaderTest::ByteFf => 1,
                        HeaderTest::WordFfff => 2,
                    });
                }
                self.count(domains.len())?;
                for d in domains {
                    self.word(d.first);
                    self.word(d.last);
                    self.count(d.region)?;
                }
            }
            ParameterLayout::SerialRange {
                address_bits,
                first_word,
                word_count,
                encoding,
            } => {
                self.byte(2);
                self.byte(*address_bits);
                self.word(*first_word);
                self.word(*word_count);
                self.encoding(*encoding);
            }
            ParameterLayout::SerialSelected {
                address_bits,
                bases,
                slots,
                selection,
                encoding,
            } => {
                self.byte(3);
                self.byte(*address_bits);
                for b in bases {
                    self.word(*b);
                }
                self.0.extend(slots);
                self.encoding(*encoding);
                match selection {
                    SerialSelection::Header(h) => {
                        self.byte(1);
                        self.word(*h);
                    }
                    SerialSelection::FallbackWords(words) => {
                        self.byte(2);
                        for w in words {
                            self.word(*w);
                        }
                    }
                }
            }
        }
        Some(())
    }
    fn peripheral_geometry(&mut self, g: &geometry::PeripheralGeometry) -> Option<()> {
        match g {
            geometry::PeripheralGeometry::FlashRecords(records) => {
                self.byte(1);
                self.count(records.len())?;
                for (a, n) in records {
                    self.long(*a);
                    self.long(*n);
                }
            }
            geometry::PeripheralGeometry::SerialWords { first, last } => {
                self.byte(2);
                self.word(*first);
                self.word(*last);
            }
            geometry::PeripheralGeometry::SerialRecords { bases, slots } => {
                self.byte(3);
                for b in bases {
                    self.word(*b);
                }
                self.0.extend(slots);
            }
        }
        Some(())
    }
    fn ata_input(&mut self, v: AtaInput) {
        match v {
            AtaInput::M32c(input) => {
                self.byte(1);
                match input {
                    peripheral::Input::LoadingLimits {
                        address,
                        closed_bit,
                        opened_bit,
                        active,
                        open_first,
                    } => {
                        self.byte(1);
                        self.long(address);
                        self.byte(closed_bit);
                        self.byte(opened_bit);
                        self.byte(u8::from(active));
                        self.byte(u8::from(open_first));
                    }
                    peripheral::Input::KeyEvent {
                        address,
                        mask,
                        required,
                    } => {
                        self.byte(2);
                        self.long(address);
                        self.byte(mask);
                        self.byte(required);
                    }
                }
            }
            AtaInput::V850(algorithm) => {
                self.byte(2);
                self.byte(match algorithm {
                    peripheral::KeyAlgorithm::CounterLow => 1,
                    peripheral::KeyAlgorithm::TimerLow => 2,
                    peripheral::KeyAlgorithm::HighFallingSelected => 3,
                    peripheral::KeyAlgorithm::LowRisingSelected => 4,
                    peripheral::KeyAlgorithm::LowRisingMode => 5,
                });
            }
        }
    }
}
fn digest(bytes: &[u8]) -> Family {
    let hash = Sha256::digest(bytes);
    Family(u64::from_be_bytes(
        hash[..8].try_into().expect("eight-byte digest prefix"),
    ))
}
impl SatKey {
    /// Versioned canonical binary key, independent of labels, evidence addresses
    /// and native host endianness. None only if a vector cannot fit a u32 count.
    pub fn canonical_bytes(&self) -> Option<Vec<u8>> {
        let mut e = Encoder::new();
        match self {
            Self::Sat1 {
                geometry,
                irq,
                phase,
                layout,
            } => {
                e.byte(1);
                e.geometry(geometry);
                e.irq(irq);
                e.assignment(Some(*phase));
                e.layout(layout)?;
            }
            Self::Sat8 {
                input_flags,
                host,
                irq,
                phase,
                layout,
            } => {
                e.byte(8);
                e.byte(*input_flags);
                e.byte(*host);
                e.irq(irq);
                e.assignment(*phase);
                e.layout(layout)?;
            }
            Self::Sat9 {
                geometry,
                host,
                phase,
                layout,
            } => {
                e.byte(9);
                e.geometry(geometry);
                e.byte(*host);
                e.assignment(*phase);
                e.layout(layout)?;
            }
        }
        Some(e.0)
    }
    /// First eight SHA-256 bytes of the versioned canonical binary key.
    /// A candidate digest never grants correction or update permission.
    pub fn family(&self) -> Option<Family> {
        Some(digest(&self.canonical_bytes()?))
    }
}
impl AtaKey {
    /// Versioned canonical binary ATA key. Architecture and input algorithm have
    /// separate tags; native interface, source assignment and layout are retained.
    pub fn canonical_bytes(&self) -> Option<Vec<u8>> {
        let mut e = Encoder::new();
        e.byte(0xa0);
        e.peripheral_geometry(&self.geometry)?;
        e.layout(&self.layout)?;
        for value in [
            self.host.coordinate,
            self.host.signature_low,
            self.host.signature_high,
            self.host.initial_one[0],
            self.host.initial_one[1],
        ] {
            e.long(value);
        }
        e.ata_input(self.input);
        e.assignment(Some(self.phase.assignment));
        match self.phase.interface {
            peripheral::Interface::Direct8 { channels } => {
                e.byte(1);
                for c in channels {
                    e.long(c);
                }
            }
            peripheral::Interface::Indexed16 { window, channels } => {
                e.byte(2);
                e.long(window);
                for c in channels {
                    e.long(c);
                }
            }
        }
        Some(e.0)
    }
    /// First eight SHA-256 bytes of the versioned canonical binary ATA key.
    pub fn family(&self) -> Option<Family> {
        Some(digest(&self.canonical_bytes()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(phase: Option<Assignment>) -> SatKey {
        SatKey::Sat8 {
            input_flags: 4,
            host: 0x80,
            irq: irq::Value::Controller {
                and_mask: 0xff,
                or_mask: 0x20,
            },
            phase,
            layout: ParameterLayout::SerialRange {
                address_bits: 16,
                first_word: 0xc0,
                word_count: 160,
                encoding: WordEncoding::SerialHighByteFirst,
            },
        }
    }
    #[test]
    fn canonical_bytes_and_digest_match_independent_big_endian_vectors() {
        // Built independently using Python bytes/struct and hashlib.sha256.
        for (phase, tag, hash) in [
            (None, 0, "95cf989a05f6220e"),
            (Some(Assignment::Direct), 1, "c127704406a2ac1f"),
            (Some(Assignment::Swapped), 2, "e6adb13052ed8295"),
        ] {
            let mut expected = b"PIONEER-FAMILY\0\x06".to_vec();
            expected.extend([8, 4, 128, 1, 255, 32, tag, 2, 16, 0, 192, 0, 160, 3]);
            assert_eq!(key(phase).canonical_bytes().unwrap(), expected);
            assert_eq!(key(phase).family().unwrap().to_string(), hash);
        }
    }
    #[test]
    fn layout_options_variants_and_native_encoding_have_distinct_encodings() {
        let base = RecordRegion {
            address: 0x7f0000,
            basis: AddressBasis::Absolute,
            allocation_bytes: None,
            record_bytes: 320,
            record_count: 40,
            header_bytes: 80,
            header_test: HeaderTest::ByteFf,
        };
        let encode = |r: RecordRegion, encoding: WordEncoding, domain: LogicalDomain| {
            let mut e = Encoder::new();
            e.layout(&ParameterLayout::FlashRecords {
                regions: alloc::vec![r],
                encoding,
                domains: alloc::vec![domain],
            })
            .unwrap();
            e.0
        };
        let domain = LogicalDomain {
            first: 0,
            last: 159,
            region: 0,
        };
        let initial = encode(base.clone(), WordEncoding::LittleEndian, domain.clone());
        let mut variants = Vec::new();
        for field in 0..7 {
            let mut r = base.clone();
            match field {
                0 => r.address += 1,
                1 => r.basis = AddressBasis::SelectedBank,
                2 => r.allocation_bytes = Some(0),
                3 => r.record_bytes += 1,
                4 => r.record_count += 1,
                5 => r.header_bytes += 1,
                _ => r.header_test = HeaderTest::WordFfff,
            }
            variants.push(encode(r, WordEncoding::LittleEndian, domain.clone()));
        }
        variants.push(encode(
            base.clone(),
            WordEncoding::DirectOrBusPermutedLittleEndian,
            domain.clone(),
        ));
        for field in 0..3 {
            let mut d = domain.clone();
            match field {
                0 => d.first += 1,
                1 => d.last += 1,
                _ => d.region += 1,
            };
            variants.push(encode(base.clone(), WordEncoding::LittleEndian, d));
        }
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(*v, initial);
            assert!(!variants[..i].contains(v));
        }
    }
}
