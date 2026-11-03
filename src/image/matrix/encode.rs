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
    fn hex(s: &str) -> Vec<u8> {
        let mut out = b"PIONEER-FAMILY\0\x06".to_vec();
        out.extend(
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()),
        );
        out
    }
    fn flash(
        address: u32,
        basis: AddressBasis,
        allocation_bytes: Option<u32>,
        (record_count, header_bytes, header_test): (u16, u16, HeaderTest),
        encoding: WordEncoding,
    ) -> ParameterLayout {
        ParameterLayout::FlashRecords {
            regions: alloc::vec![RecordRegion {
                address,
                basis,
                allocation_bytes,
                record_bytes: 320,
                record_count,
                header_bytes,
                header_test,
            }],
            encoding,
            domains: alloc::vec![LogicalDomain {
                first: 0,
                last: 159,
                region: 0,
            }],
        }
    }
    #[test]
    fn every_key_variant_matches_independent_byte_vectors() {
        // Expected bytes built independently with Python struct (big endian).
        let slots = [8, 10, 11, 9, 12, 0, 1, 2];
        let sat = [
            (
                SatKey::Sat1 {
                    geometry: geometry::Geometry::MarkerBanks {
                        marker: 0xfedc4321,
                        stride: 0x10000,
                    },
                    irq: irq::Value::Controller {
                        and_mask: 0,
                        or_mask: 0x20,
                    },
                    phase: Assignment::Direct,
                    layout: flash(
                        0x7f0000,
                        AddressBasis::Absolute,
                        None,
                        (40, 80, HeaderTest::ByteFf),
                        WordEncoding::LittleEndian,
                    ),
                },
                "0101fedc43210001000001002001010100000001007f00000100000001400028005001000000010000009f00000000",
            ),
            (
                SatKey::Sat9 {
                    geometry: geometry::Geometry::NativeBanks {
                        bases: [0x7d0000, 0x7e0000],
                        stride: 0x10000,
                    },
                    host: 0x80,
                    phase: Some(Assignment::Swapped),
                    layout: flash(
                        0x9984,
                        AddressBasis::SelectedBank,
                        Some(0x3400),
                        (20, 40, HeaderTest::WordFfff),
                        WordEncoding::DirectOrBusPermutedLittleEndian,
                    ),
                },
                "0902007d0000007e000000010000800201020000000100009984020100003400000001400014002802000000010000009f00000000",
            ),
            (
                SatKey::Sat8 {
                    input_flags: 2,
                    host: 0,
                    irq: irq::Value::Input(inputs::Term {
                        address: 0xff414000,
                        encoding: inputs::Encoding::Absolute32,
                        bit: 1,
                        active: false,
                    }),
                    phase: None,
                    layout: ParameterLayout::SerialSelected {
                        address_bits: 10,
                        bases: [0x220, 0x260],
                        slots,
                        selection: SerialSelection::Header(0x256),
                        encoding: WordEncoding::SerialHighByteFirst,
                    },
                },
                "0802000202ff414000010000030a02200260080a0b090c00010203010256",
            ),
        ];
        for (key, expected) in sat {
            assert_eq!(key.canonical_bytes().unwrap(), hex(expected), "{key:?}");
        }
        let host = |base: u32| peripheral::HostSignature {
            coordinate: base,
            signature_low: base,
            signature_high: base + 1,
            initial_one: [base + 2, base + 3],
        };
        let ata = [
            (
                AtaKey {
                    geometry: geometry::PeripheralGeometry::SerialRecords {
                        bases: [0x220, 0x260],
                        slots,
                    },
                    layout: ParameterLayout::SerialSelected {
                        address_bits: 10,
                        bases: [0x220, 0x260],
                        slots,
                        selection: SerialSelection::FallbackWords([
                            0x240, 0x242, 0x243, 0x241, 0x246, 0x247, 0x245, 0x244,
                        ]),
                        encoding: WordEncoding::SerialHighByteFirst,
                    },
                    host: host(0x2000d2),
                    input: AtaInput::M32c(peripheral::Input::LoadingLimits {
                        address: 385,
                        closed_bit: 6,
                        opened_bit: 7,
                        active: false,
                        open_first: true,
                    }),
                    phase: peripheral::Phase {
                        assignment: Assignment::Direct,
                        interface: peripheral::Interface::Indexed16 {
                            window: 0x200100,
                            channels: [0x8e, 0x8f],
                        },
                    },
                },
                "a00302200260080a0b090c000102030a02200260080a0b090c000102030202400242024302410246024702450244002000d2002000d2002000d3002000d4002000d5010100000181060700010102002001000000008e0000008f",
            ),
            (
                AtaKey {
                    geometry: geometry::PeripheralGeometry::FlashRecords(alloc::vec![
                        (0x1000, 0x100),
                        (0x2000, 0x100),
                    ]),
                    layout: ParameterLayout::SerialRange {
                        address_bits: 10,
                        first_word: 0xc0,
                        word_count: 160,
                        encoding: WordEncoding::SerialHighByteFirst,
                    },
                    host: host(0x56f9),
                    input: AtaInput::V850(peripheral::KeyAlgorithm::TimerLow),
                    phase: peripheral::Phase {
                        assignment: Assignment::Swapped,
                        interface: peripheral::Interface::Direct8 {
                            channels: [0x118, 0x119],
                        },
                    },
                },
                "a0010000000200001000000001000000200000000100020a00c000a003000056f9000056f9000056fa000056fb000056fc020202010000011800000119",
            ),
            (
                AtaKey {
                    geometry: geometry::PeripheralGeometry::SerialWords {
                        first: 0xc0,
                        last: 0x15f,
                    },
                    layout: ParameterLayout::SerialRange {
                        address_bits: 10,
                        first_word: 0xc0,
                        word_count: 160,
                        encoding: WordEncoding::SerialHighByteFirst,
                    },
                    host: peripheral::HostSignature {
                        coordinate: 1,
                        signature_low: 2,
                        signature_high: 3,
                        initial_one: [4, 5],
                    },
                    input: AtaInput::M32c(peripheral::Input::KeyEvent {
                        address: 420,
                        mask: 0x10,
                        required: 0,
                    }),
                    phase: peripheral::Phase {
                        assignment: Assignment::Direct,
                        interface: peripheral::Interface::Direct8 {
                            channels: [0x54ca, 0x54cb],
                        },
                    },
                },
                "a00200c0015f020a00c000a00300000001000000020000000300000004000000050102000001a410000101000054ca000054cb",
            ),
        ];
        for (key, expected) in ata {
            assert_eq!(key.canonical_bytes().unwrap(), hex(expected), "{key:?}");
        }
    }
}
