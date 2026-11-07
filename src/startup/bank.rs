//! Persistent-bank header requirements, separate from native parameter words.
//! Offsets and expected values are operands in validated code, not model rules.

use alloc::vec::Vec;

const BASE: u32 = 0x410000;

mod legacy;
pub(crate) use legacy::{legacy_predicate_witness, LegacyPredicateBank};
#[cfg(test)]
mod tests;

/// Persistent header locations extracted from the firmware's addressing code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addresses {
    /// An older implementation uses absolute addresses.
    Fixed([u32; 2]),
    /// A capacity discriminator selects one of two address expressions.
    /// Equality records the two address cases, not equivalence of the native
    /// discriminator programs or their external service effects.
    Capacity {
        /// Addresses when the discriminator returns one.
        when_one: [u32; 2],
        /// Addresses for the other results.
        otherwise: [u32; 2],
    },
}

/// How the recognized startup code treats nonmatching, nonblank headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Validation {
    /// Either matching header is accepted; neither matching enters the loader.
    RejectMismatch,
    /// Initialize when both are blank, then select a bank without a rejection.
    InitializeAndSelect,
}

/// Storage requirements, independent of code relocation and native word 009F.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contract {
    /// Header value used by initialization and bank selection.
    pub magic: u32,
    /// Addresses, including each recognized capacity case.
    pub addresses: Addresses,
    /// Observed mismatch behavior; initialization alone is not a rejecting guard.
    pub validation: Validation,
}

/// Recognized persistent storage generation. These are different contracts,
/// not interchangeable spellings of a missing marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Storage {
    /// Initialization and selection use a versioned header.
    Versioned(Contract),
    /// Earlier Normal validates erased header state and sequence words.
    StateHeaders {
        /// Two longwords of state per bank.
        headers: [[u32; 2]; 2],
        /// Sequence counter address per bank.
        sequences: [u32; 2],
        /// Additional per-bank state words consulted by selection.
        status: [u32; 2],
    },
    /// Earlier Kernel owns the banks and selects by sequence words.
    KernelSequences {
        /// Sequence counter address per bank.
        sequences: [u32; 2],
        /// Base address per bank.
        bases: [u32; 2],
    },
}

/// Analyze both decoded components. Missing evidence remains unresolved.
pub fn analyze_pair(normal: &[u8], kernel: Option<&[u8]>) -> Option<Storage> {
    if let Some(contract) = analyze(normal) {
        return Some(Storage::Versioned(contract));
    }
    if let Some(contract) = legacy::state_banks(normal) {
        return Some(contract);
    }
    // Kernel-owned storage is accepted only with a decoded Normal which has
    // an independently recognized native receiver, and a complete Kernel.
    let kernel = kernel?;
    if kernel.len() != 0x10000 || crate::image::receiver_control(normal).is_none() {
        return None;
    }
    legacy::state_selector(kernel, 0x400000).or_else(|| legacy::kernel_sequences(kernel))
}

/// A storage transition cannot be established from the supplied components.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Installed storage requirements could not be recovered.
    UnknownInstalled,
    /// Target storage requirements could not be recovered.
    UnknownTarget,
    /// The storage formats differ. No conversion exists under any policy.
    ConversionRequired {
        /// Installed code-derived storage contract.
        installed: Storage,
        /// Target code-derived storage contract.
        target: Storage,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::UnknownInstalled=>"installed persistent bank requirements are unresolved; provide the installed Kernel and Normal; no settings or firmware were written",
            Self::UnknownTarget=>"target persistent bank requirements are unresolved; provide the target Kernel and Normal; no settings or firmware were written",
            Self::ConversionRequired{..}=>"persistent bank formats differ and no bank conversion exists; no settings or firmware were written",
        })
    }
}
impl std::error::Error for Error {}
impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::UnknownInstalled => "pioneer.startup.bank_unknown_installed",
            Self::UnknownTarget => "pioneer.startup.bank_unknown_target",
            Self::ConversionRequired { .. } => "pioneer.startup.bank_conversion_required",
        }
    }
}

/// Check storage independently of family equality and native word migration.
/// No header writes, erased-value assumptions, or implicit conversions occur.
pub fn check(installed: Option<Storage>, target: Option<Storage>) -> Result<(), Error> {
    let installed = installed.ok_or(Error::UnknownInstalled)?;
    let target = target.ok_or(Error::UnknownTarget)?;
    if installed == target {
        Ok(())
    } else {
        Err(Error::ConversionRequired { installed, target })
    }
}

#[cfg(test)]
pub(crate) fn fixture(normal: &mut [u8]) {
    legacy::fixture(normal);
}

#[cfg(all(test, feature = "envelope"))]
pub(crate) fn versioned_fixture(magic: u32, markers: [u32; 2]) -> Vec<u8> {
    tests::versioned_with(magic, markers)
}

/// Recover a storage contract. `None` means unresolved, never "no check".
pub fn analyze(normal: &[u8]) -> Option<Contract> {
    if let Some(guard) = discover(normal) {
        let layout = guard.layout(normal)?;
        return Some(Contract {
            magic: guard.magic,
            addresses: Addresses::Capacity {
                when_one: layout.when_one.markers,
                otherwise: layout.otherwise.markers,
            },
            validation: Validation::RejectMismatch,
        });
    }
    legacy::discover(normal).map(|fixed| Contract {
        magic: fixed.magic,
        addresses: Addresses::Fixed(fixed.markers),
        validation: if fixed.rejects {
            Validation::RejectMismatch
        } else {
            Validation::InitializeAndSelect
        },
    })
}

/// One startup guard accepting either of two persistent-bank headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirement {
    /// CPU address of the validator function.
    pub validator: u32,
    /// RAM slot containing the runtime persistent-storage base address.
    pub base_slot: u32,
    /// Required 32-bit header value, independent of any native word index.
    pub magic: u32,
    /// Header offsets relative to the runtime base, in firmware order.
    pub marker_offsets: [u32; 2],
    /// Routine setting the Kernel loader flag on rejection.
    pub reject_helper: u32,
}

impl Requirement {
    /// Resolve header locations only after the runtime bank base is known.
    pub fn addresses(self, base: u32) -> Option<[u32; 2]> {
        Some([
            base.checked_add(self.marker_offsets[0])?,
            base.checked_add(self.marker_offsets[1])?,
        ])
    }

    /// Bank spacing extracted from the two header reads.
    pub fn stride(self) -> Option<u32> {
        self.marker_offsets[1].checked_sub(self.marker_offsets[0])
    }

    /// Recover the unique code calculation supplying this guard's base slot.
    pub fn layout(self, normal: &[u8]) -> Option<Layout> {
        let mut calls = None;
        let mut found = (0..normal.len().saturating_sub(0x35))
            .step_by(2)
            .filter_map(|at| base_calculation(normal, at, self, &mut calls));
        let result = found.next()?;
        found.next().is_none().then_some(result)
    }
}

/// Addresses derived for the two outcomes of the firmware's capacity query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Function calculating and storing the persistent base.
    pub calculation: u32,
    /// Called capacity discriminator; its live result selects the case.
    pub capacity_query: u32,
    /// Base and marker addresses when the discriminator returns one.
    pub when_one: BankAddresses,
    /// Base and marker addresses for the other discriminator results.
    pub otherwise: BankAddresses,
}

/// One evaluated persistent-bank address expression.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BankAddresses {
    /// Runtime persistent-storage base, calculated from code operands.
    pub base: u32,
    /// Two alternative header locations.
    pub markers: [u32; 2],
}

// Sorted (first, second) targets of every pair of adjacent native calls.
fn call_pairs(normal: &[u8]) -> Vec<(u32, u32)> {
    #[cfg(test)]
    base_calculation_tests::CALL_PAIR_SCANS.with(|c| c.set(c.get() + 1));
    let mut pairs: Vec<(u32, u32)> = (0..normal.len().saturating_sub(7))
        .step_by(2)
        .filter_map(|p| call(normal, p).zip(call(normal, p + 4)))
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

fn base_calculation(
    normal: &[u8],
    at: usize,
    guard: Requirement,
    calls: &mut Option<Vec<(u32, u32)>>,
) -> Option<Layout> {
    let b = normal.get(at..)?;
    let query = call(b, 0)?;
    if b.get(4..6)? != [0x7a, 1] || b.get(10..16)? != [0xa8, 1, 0x46, 4, 0x79, 9] {
        return None;
    }
    let end = word(b, 6)?;
    let compact_end = (end & 0xffff) | (u32::from(u16::from_be_bytes([b[16], b[17]])) << 16);
    // Equal ends make the when-one path fall through to the extended
    // subtraction, so the modeled compact case is not what the code computes.
    if compact_end == end {
        return None;
    }
    let (compare, increment, register) = if b.get(18..22)? == [0x0f, 0x90, 0x0b, 0x70] {
        (22, 1u32, 0)
    } else {
        (18, 0u32, 1)
    };
    if b.get(compare..compare + 2)? != [0x7a, 0x21]
        || word(b, compare + 2)? != end
        || b.get(compare + 6..compare + 10)? != [0x46, 8, 0x7a, 0x30 + register]
        || b.get(compare + 14..compare + 18)? != [0x40, 6, 0x7a, 0x30 + register]
        || b.get(compare + 22..compare + 26)? != [1, 0, 0x6b, 0xa0 + register]
        || word(b, compare + 26)? != guard.base_slot
        || b.get(compare + 30..compare + 32)? != [0x54, 0x70]
    {
        return None;
    }
    let extended_base = end
        .checked_add(increment)?
        .checked_sub(word(b, compare + 10)?)?;
    let compact_base = compact_end
        .checked_add(increment)?
        .checked_sub(word(b, compare + 18)?)?;
    let calculation = BASE.checked_add(at as u32)?;
    // Bind the calculation and validator to the adjacent calls actually used
    // by startup. Merely storing into a similarly numbered slot is insufficient.
    if calls
        .get_or_insert_with(|| call_pairs(normal))
        .binary_search(&(calculation, guard.validator))
        .is_err()
    {
        return None;
    }
    Some(Layout {
        calculation,
        capacity_query: query,
        when_one: BankAddresses {
            base: compact_base,
            markers: guard.addresses(compact_base)?,
        },
        otherwise: BankAddresses {
            base: extended_base,
            markers: guard.addresses(extended_base)?,
        },
    })
}

fn word(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn call(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at + 4)?;
    (b[0] == 0x5e).then(|| u32::from_be_bytes([0, b[1], b[2], b[3]]))
}

fn loader_helper(normal: &[u8], address: u32) -> Option<()> {
    let at = address.checked_sub(BASE)? as usize;
    let b = normal.get(at..at + 14)?;
    if b[..2] != [0xf8, 1] || b[6..8] != [0xf8, 1] || b[12..] != [0x18, 0x88] {
        return None;
    }
    for (at, service) in [(2, 0x14), (8, 0x1a)] {
        let wrapper = call(b, at)?.checked_sub(BASE)? as usize;
        if normal.get(wrapper..wrapper + 6)? != [0x5e, 0x40, 0x0a, service, 0x54, 0x70] {
            return None;
        }
    }
    Some(())
}

fn candidate(normal: &[u8], at: usize) -> Option<Requirement> {
    let b = normal.get(at..at + 0x92)?;
    for (offset, expected) in [
        (
            0,
            &b"\x01\x00\x6d\xf3\x01\x20\x6d\xf4\x79\x37\x00\x06\x7a\x05"[..],
        ),
        (0x12, &b"\x01\x00\x6f\xf5\x00\x02\x7a\x06"[..]),
        (0x1e, &b"\x01\x00\x69\x63\x0f\xb4\x7a\x14"[..]),
        (0x2a, &b"\x69\x41\x69\xf1\x01\x00\x78\x30\x6b\x22"[..]),
        (
            0x38,
            &b"\x7a\x22\xff\xff\xff\xff\x46\x38\x01\x00\x78\x30\x6b\x20"[..],
        ),
        (0x4a, &b"\x0b\x70\x46\x2a"[..]),
        (
            0x4e,
            &b"\x79\x01\x00\x01\x69\xf1\x0f\xf1\x79\x02\x00\x01\x0f\xc0"[..],
        ),
        (0x60, &b"\x01\x00\x69\x60\x7a\x10"[..]),
        (0x6a, &b"\x0f\xf1\x0b\xf1\x79\x02\x00\x02"[..]),
        (0x76, &b"\x40\x16"[..]),
        (0x78, &b"\x1f\xd2\x47\x12\x01\x00\x78\x30\x6b\x20"[..]),
        (0x86, &b"\x1f\xd0\x47\x04"[..]),
        (0x8e, &b"\x79\x17\x00\x06"[..]),
    ] {
        if b.get(offset..offset + expected.len())? != expected {
            return None;
        }
    }
    let magic = word(b, 0xe)?;
    let first = word(b, 0x34)?;
    let second = word(b, 0x46)?;
    if magic == u32::MAX
        || first.checked_add(4)? != word(b, 0x26)?
        || second <= first
        || second != word(b, 0x82)?
        || first != word(b, 0x66)?
        || call(b, 0x5c)? != call(b, 0x72)?
    {
        return None;
    }
    let reject_helper = call(b, 0x8a)?;
    loader_helper(normal, reject_helper)?;
    Some(Requirement {
        validator: BASE.checked_add(at as u32)?,
        base_slot: word(b, 0x1a)?,
        magic,
        marker_offsets: [first, second],
        reject_helper,
    })
}

/// Recover a unique supported bank-header validator, or unknown.
/// This identifies code evidence only: it neither reads banks nor authorizes
/// changing a marker. Unknown does not establish absence of another guard.
pub fn discover(normal: &[u8]) -> Option<Requirement> {
    let mut matches = (0..normal.len().saturating_sub(0x91))
        .step_by(2)
        .filter_map(|at| candidate(normal, at));
    let result = matches.next()?;
    matches.next().is_none().then_some(result)
}

#[cfg(test)]
mod base_calculation_tests {
    use super::*;
    use core::cell::Cell;

    std::thread_local! {
        pub(super) static CALL_PAIR_SCANS: Cell<usize> = const { Cell::new(0) };
    }

    fn put(b: &mut [u8], at: usize, bytes: &[u8]) {
        b[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn call_to(target: u32) -> [u8; 4] {
        let t = target.to_be_bytes();
        [0x5e, t[1], t[2], t[3]]
    }

    // Synthetic capacity guard: validator at 0x100, reject helper at 0x200,
    // base calculation at 0x300 and the adjacent startup calls at 0x400.
    fn capacity_fixture(compact: u16) -> Vec<u8> {
        let mut b = vec![0xff; 0x1000];
        let g = 0x100;
        for (offset, bytes) in [
            (
                0,
                &b"\x01\x00\x6d\xf3\x01\x20\x6d\xf4\x79\x37\x00\x06\x7a\x05"[..],
            ),
            (0x12, &b"\x01\x00\x6f\xf5\x00\x02\x7a\x06"[..]),
            (0x1e, &b"\x01\x00\x69\x63\x0f\xb4\x7a\x14"[..]),
            (0x2a, &b"\x69\x41\x69\xf1\x01\x00\x78\x30\x6b\x22"[..]),
            (
                0x38,
                &b"\x7a\x22\xff\xff\xff\xff\x46\x38\x01\x00\x78\x30\x6b\x20"[..],
            ),
            (0x4a, &b"\x0b\x70\x46\x2a"[..]),
            (
                0x4e,
                &b"\x79\x01\x00\x01\x69\xf1\x0f\xf1\x79\x02\x00\x01\x0f\xc0"[..],
            ),
            (0x60, &b"\x01\x00\x69\x60\x7a\x10"[..]),
            (0x6a, &b"\x0f\xf1\x0b\xf1\x79\x02\x00\x02"[..]),
            (0x76, &b"\x40\x16"[..]),
            (0x78, &b"\x1f\xd2\x47\x12\x01\x00\x78\x30\x6b\x20"[..]),
            (0x86, &b"\x1f\xd0\x47\x04"[..]),
            (0x8e, &b"\x79\x17\x00\x06"[..]),
        ] {
            put(&mut b, g + offset, bytes);
        }
        let (first, second, slot) = (0x0efffau32, 0x0ffffau32, 0x00ffe000u32);
        for (offset, value) in [
            (0xe, 0xfedc4321u32),
            (0x1a, slot),
            (0x26, first + 4),
            (0x34, first),
            (0x46, second),
            (0x66, first),
            (0x82, second),
        ] {
            put(&mut b, g + offset, &value.to_be_bytes());
        }
        for offset in [0x5c, 0x72] {
            put(&mut b, g + offset, &call_to(BASE + 0x800));
        }
        put(&mut b, g + 0x8a, &call_to(BASE + 0x200));
        put(&mut b, 0x200, &[0xf8, 1]);
        put(&mut b, 0x202, &call_to(BASE + 0x220));
        put(&mut b, 0x206, &[0xf8, 1]);
        put(&mut b, 0x208, &call_to(BASE + 0x228));
        put(&mut b, 0x20c, &[0x18, 0x88]);
        put(&mut b, 0x220, &[0x5e, 0x40, 0x0a, 0x14, 0x54, 0x70]);
        put(&mut b, 0x228, &[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        // ER1 = end; when the query returns one, E1 = compact; compare with
        // end and subtract the matching bank span.
        let end = 0x0080_0000u32;
        let c = 0x300;
        put(&mut b, c, &call_to(BASE + 0x900));
        put(&mut b, c + 4, &[0x7a, 1]);
        put(&mut b, c + 6, &end.to_be_bytes());
        put(&mut b, c + 10, &[0xa8, 1, 0x46, 4, 0x79, 9]);
        put(&mut b, c + 16, &compact.to_be_bytes());
        put(&mut b, c + 18, &[0x7a, 0x21]);
        put(&mut b, c + 20, &end.to_be_bytes());
        put(&mut b, c + 24, &[0x46, 8, 0x7a, 0x31]);
        put(&mut b, c + 28, &0x0010_0000u32.to_be_bytes());
        put(&mut b, c + 32, &[0x40, 6, 0x7a, 0x31]);
        put(&mut b, c + 36, &0x0010_0000u32.to_be_bytes());
        put(&mut b, c + 40, &[1, 0, 0x6b, 0xa1]);
        put(&mut b, c + 44, &slot.to_be_bytes());
        put(&mut b, c + 48, &[0x54, 0x70]);
        put(&mut b, 0x400, &call_to(BASE + 0x300));
        put(&mut b, 0x404, &call_to(BASE + 0x100));
        b
    }

    #[test]
    fn capacity_calculation_recovers_both_address_cases() {
        let b = capacity_fixture(0x0060);
        assert_eq!(
            analyze(&b),
            Some(Contract {
                magic: 0xfedc4321,
                addresses: Addresses::Capacity {
                    when_one: [0x5efffa, 0x5ffffa],
                    otherwise: [0x7efffa, 0x7ffffa],
                },
                validation: Validation::RejectMismatch,
            })
        );
    }

    #[test]
    fn compact_end_equal_to_end_does_not_model_the_when_one_branch() {
        // With E1 already equal to end's upper word, the when-one path falls
        // through to the extended subtraction; the modeled case is not taken.
        let b = capacity_fixture(0x0080);
        assert_eq!(analyze(&b), None);
    }

    #[test]
    fn calculation_lookalikes_share_one_call_index() {
        let mut b = capacity_fixture(0x0060);
        for at in (0x500..0xa00).step_by(0x40) {
            b.copy_within(0x300..0x332, at);
        }
        CALL_PAIR_SCANS.with(|c| c.set(0));
        assert!(matches!(
            analyze(&b),
            Some(Contract {
                addresses: Addresses::Capacity { .. },
                ..
            })
        ));
        assert!(CALL_PAIR_SCANS.with(Cell::get) <= 1);
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use crate::CodedError;
    #[test]
    fn unknown_and_changed_contracts_keep_distinct_public_refusals() {
        let contract = Storage::KernelSequences {
            sequences: [0x5efffe, 0x5ffffe],
            bases: [0x5e0000, 0x5f0000],
        };
        let other = Storage::StateHeaders {
            headers: [[1, 2], [3, 4]],
            sequences: [5, 6],
            status: [7, 8],
        };
        assert_eq!(check(Some(contract), Some(contract)), Ok(()));
        for (result, code, phrase) in [
            (
                check(None, Some(contract)),
                "pioneer.startup.bank_unknown_installed",
                "installed",
            ),
            (
                check(Some(contract), None),
                "pioneer.startup.bank_unknown_target",
                "target",
            ),
            (
                check(Some(contract), Some(other)),
                "pioneer.startup.bank_conversion_required",
                "conversion",
            ),
        ] {
            let error = result.unwrap_err();
            assert_eq!(error.code(), code);
            assert!(error.to_string().contains(phrase));
        }
    }
    #[test]
    fn address_resolution_rejects_overflow_in_either_bank_and_reverse_stride() {
        let mut guard = Requirement {
            validator: 0x5509e8,
            base_slot: 0x10,
            magic: 0xfedc4322,
            marker_offsets: [0xbffa, 0x17ffa],
            reject_helper: 0x4afa7c,
        };
        assert_eq!(guard.stride(), Some(0xc000));
        assert_eq!(guard.addresses(0x5e8000), Some([0x5f3ffa, 0x5ffffa]));
        assert_eq!(guard.addresses(u32::MAX - 0xbffa + 1), None);
        assert_eq!(guard.addresses(u32::MAX - 0xbffa), None);
        guard.marker_offsets.reverse();
        assert_eq!(guard.stride(), None);
        assert_eq!(guard.layout(&[]), None);
        assert_eq!(analyze_pair(&[], None), None);
        assert_eq!(analyze_pair(&[], Some(&[])), None);
        assert_eq!(analyze_pair(&[], Some(&vec![0; 0x10000])), None);
    }
}
