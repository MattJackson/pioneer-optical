//! Read-only binding of one audited Normal-mode native programmer.
//!
//! This is instruction evidence, not permission to program a bank. No command
//! is sent and no conversion, free RAM reservation, interrupt exclusion or
//! power-loss recovery is established here. Kernel-mode vectors are different.
#[path = "programmer_bytes.rs"]
mod audited;

const NORMAL_BASE: usize = 0x410000;
const CONSTRUCTOR: usize = 0x4ae5b6;
const COPY_SOURCE: usize = 0x57e8fc;
const COPY_RAM: u32 = 0x4be;

/// Source-derived native ABI after the audited Normal startup copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    _private: (),
}
impl Evidence {
    /// Native erase entry: ER0 is flash-relative offset; ER1 is byte count.
    pub fn erase_entry(self) -> u32 {
        0x4f0
    }
    /// Native program entry: ER0 is flash-relative offset; ER1 is source RAM;
    /// R2 is a word count. The native loop splits writes on 256-byte boundaries.
    pub fn program_entry(self) -> u32 {
        0x53c
    }
    /// Native sector query returns 0x10000 for this audited implementation.
    pub fn sector_size(self) -> u32 {
        0x10000
    }
    /// Address base subtracted from CPU flash addresses for both native calls.
    pub fn flash_base(self) -> u32 {
        0x400000
    }
    /// Current-mode code interval which must be read back without short reads.
    pub fn runtime_interval(self) -> (u32, usize) {
        (COPY_RAM, audited::COPIED.len())
    }
    /// Exact relocated instruction comparison. A match establishes only that
    /// these vectors still contain the audited code, not that mutation is safe.
    pub fn matches_runtime(self, bytes: &[u8]) -> bool {
        bytes == audited::COPIED
    }
    /// Validate native argument widths and physical erase alignment before a
    /// higher-level transaction considers this ABI. This does not authorize an
    /// address; the live bank/ownership plan must impose its own narrower range.
    pub fn arguments_fit(self, cpu: u32, length: u32, erase: bool) -> bool {
        let Some(offset) = cpu.checked_sub(self.flash_base()) else {
            return false;
        };
        if length == 0 || cpu.checked_add(length).is_none() || offset.checked_add(length).is_none()
        {
            return false;
        }
        if erase {
            offset % self.sector_size() == 0 && length % self.sector_size() == 0
        } else {
            // R2 is doubled in a 16-bit register before transfer. Reject the
            // otherwise silent overflow at 0x8000 words, and odd byte counts.
            offset % 2 == 0 && length % 2 == 0 && length <= 0xfffe
        }
    }
}

/// Bind the actual startup constructor and complete copied native code, not a
/// model name or a loose search for an erase/program opcode. Unknown versions
/// remain unrecognized until independently audited.
pub fn discover(normal: &[u8]) -> Option<Evidence> {
    let constructor = CONSTRUCTOR.checked_sub(NORMAL_BASE)?;
    let source = COPY_SOURCE.checked_sub(NORMAL_BASE)?;
    (normal.get(constructor..constructor + audited::STARTUP.len()) == Some(audited::STARTUP)
        && normal.get(source..source + audited::COPIED.len()) == Some(audited::COPIED))
    .then_some(Evidence { _private: () })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0; COPY_SOURCE - NORMAL_BASE + audited::COPIED.len()];
        let at = CONSTRUCTOR - NORMAL_BASE;
        bytes[at..at + audited::STARTUP.len()].copy_from_slice(audited::STARTUP);
        bytes[COPY_SOURCE - NORMAL_BASE..].copy_from_slice(audited::COPIED);
        bytes
    }
    #[test]
    fn binds_normal_vectors_and_rejects_every_changed_instruction_byte() {
        let mut bytes = fixture();
        let evidence = discover(&bytes).unwrap();
        assert_eq!(evidence.erase_entry(), 0x4f0);
        assert_eq!(evidence.program_entry(), 0x53c);
        assert_eq!(evidence.runtime_interval(), (0x4be, 0x28c));
        assert!(evidence.matches_runtime(audited::COPIED));
        assert!(!evidence.matches_runtime(&audited::COPIED[..audited::COPIED.len() - 1]));
        for (base, excerpt) in [
            (CONSTRUCTOR, audited::STARTUP),
            (COPY_SOURCE, audited::COPIED),
        ] {
            for i in 0..excerpt.len() {
                let at = base - NORMAL_BASE + i;
                bytes[at] ^= 1;
                assert_eq!(discover(&bytes), None, "changed instruction at {at:x}");
                bytes[at] ^= 1;
            }
        }
        let mut live = audited::COPIED.to_vec();
        for i in 0..live.len() {
            live[i] ^= 1;
            assert!(!evidence.matches_runtime(&live), "runtime byte {i:x}");
            live[i] ^= 1;
        }
    }
    #[test]
    fn argument_checks_reject_sector_rounding_and_word_count_overflow() {
        let evidence = discover(&fixture()).unwrap();
        assert!(evidence.arguments_fit(0x5f0000, 0x10000, true));
        assert!(evidence.arguments_fit(0x7d0000, 0x10000, true));
        assert!(!evidence.arguments_fit(0x5f4000, 0xc000, true));
        assert!(evidence.arguments_fit(0x5f4000, 0xc000, false));
        assert!(!evidence.arguments_fit(0x5f4000, 0x10000, false));
        for (cpu, len) in [
            (0x3ffffe, 2),
            (0x5f4001, 2),
            (0x5f4000, 1),
            (0x5f4000, 0),
            (0xffff0000, 0x20000),
        ] {
            assert!(!evidence.arguments_fit(cpu, len, false));
        }
        assert_eq!(discover(&[]), None);
    }
}
