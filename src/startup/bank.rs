//! Persistent-bank header requirements, separate from native parameter words.
//! Offsets and expected values are operands in validated code, not model rules.

const BASE: u32 = 0x410000;

mod legacy;

/// Persistent header locations extracted from the firmware's addressing code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Addresses {
    /// An older implementation uses absolute addresses.
    Fixed([u32; 2]),
    /// A capacity discriminator selects one of two address expressions.
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
    /// The storage formats differ and no record conversion is implemented.
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
            Self::ConversionRequired{..}=>"persistent bank format changes require a validated record conversion; no settings or firmware were written",
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
        let mut found = (0..normal.len().saturating_sub(0x35))
            .step_by(2)
            .filter_map(|at| base_calculation(normal, at, self));
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

fn base_calculation(normal: &[u8], at: usize, guard: Requirement) -> Option<Layout> {
    let b = normal.get(at..)?;
    let query = call(b, 0)?;
    if b.get(4..6)? != [0x7a, 1] || b.get(10..16)? != [0xa8, 1, 0x46, 4, 0x79, 9] {
        return None;
    }
    let end = word(b, 6)?;
    let compact_end = (end & 0xffff) | (u32::from(u16::from_be_bytes([b[16], b[17]])) << 16);
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
    if !(0..normal.len().saturating_sub(7)).step_by(2).any(|p| {
        call(normal, p) == Some(calculation) && call(normal, p + 4) == Some(guard.validator)
    }) {
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
