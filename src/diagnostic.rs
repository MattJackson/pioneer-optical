//! Mapped diagnostic read surfaces. Support varies by firmware; callers must
//! retain refusal/short-read status rather than treating zero fill as real data.

/// A bounded vendor read surface, independent of any host dump-file layout.
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    /// Stable descriptive name.
    pub name: &'static str,
    /// READ BUFFER selector.
    pub selector: u8,
    /// Starting selector-relative wire offset.
    pub offset: u32,
    /// Requested size of this mapped surface.
    pub length: usize,
    /// Maximum bytes to request in a single transfer.
    pub chunk: usize,
}
impl Surface {
    /// Encode a bounded chunk, or return `None` for invalid ranges.
    pub fn read_cdb(self, offset: usize, length: usize) -> Option<[u8; 10]> {
        if length == 0 || length > self.chunk || offset.checked_add(length)? > self.length {
            return None;
        }
        let address = self.offset.checked_add(u32::try_from(offset).ok()?)?;
        if address > 0xffffff || length > 0xffffff {
            return None;
        }
        Some(crate::cdb::diagnostic_read(
            self.selector,
            address,
            length as u32,
        ))
    }
}
/// CPU memory before B0's high-register alias.
pub const CPU_LOW: Surface = Surface {
    name: "low_memory",
    selector: 0xb0,
    offset: 0,
    length: 0x880000,
    chunk: 0x1000,
};
/// CPU registers at FFFFE000..FFFFFFFF, addressed through selector 92.
pub const CPU_HIGH: Surface = Surface {
    name: "high_registers",
    selector: 0x92,
    offset: 0,
    length: 0x2000,
    chunk: 0x100,
};
/// CPU registers at FF414000..FF4142FF, reached through B0's alias.
pub const CPU_ALIAS: Surface = Surface {
    name: "high_register_alias",
    selector: 0xb0,
    offset: 0x880000,
    length: 0x300,
    chunk: 0x300,
};
/// Controller-local address space, distinct from CPU addresses.
pub const CONTROLLER: Surface = Surface {
    name: "controller_memory",
    selector: 0x93,
    offset: 0,
    length: 0x400000,
    chunk: 0x1000,
};
/// Exact diagnostic ring response in firmware-returned order.
pub const LOG: Surface = Surface {
    name: "diagnostic_log",
    selector: 0xfc,
    offset: 0,
    length: 0x4000,
    chunk: 0x4000,
};

/// Mapped fixed diagnostic responses. These issue reads only; they do not
/// include poorly understood indexed or polling operations. FE temporarily
/// overrides the firmware's read gate and restores it before returning.
pub const RESPONSES: &[Surface] = &[
    Surface {
        name: "parameters",
        selector: 0xa0,
        offset: 0,
        length: 0x800,
        chunk: 0x800,
    },
    Surface {
        name: "peripheral_e900",
        selector: 0xd0,
        offset: 0,
        length: 0x100,
        chunk: 0x100,
    },
    Surface {
        name: "identity",
        selector: 0xf1,
        offset: 0,
        length: 0x30,
        chunk: 0x30,
    },
    Surface {
        name: "status_e0",
        selector: 0xe0,
        offset: 0,
        length: 0x20,
        chunk: 0x20,
    },
    Surface {
        name: "status_e1",
        selector: 0xe1,
        offset: 0,
        length: 0x20,
        chunk: 0x20,
    },
    Surface {
        name: "status_e5",
        selector: 0xe5,
        offset: 0,
        length: 2,
        chunk: 2,
    },
    Surface {
        name: "status_e7",
        selector: 0xe7,
        offset: 0,
        length: 0x50,
        chunk: 0x50,
    },
    Surface {
        name: "status_e6_03",
        selector: 0xe6,
        offset: 3,
        length: 4,
        chunk: 4,
    },
    Surface {
        name: "bank_window",
        selector: 0xfe,
        offset: 0,
        length: 0x4000,
        chunk: 0x4000,
    },
    Surface {
        name: "record_a",
        selector: 0xa4,
        offset: 0,
        length: 0x114,
        chunk: 0x114,
    },
    Surface {
        name: "record_b",
        selector: 0xa8,
        offset: 0,
        length: 0x164,
        chunk: 0x164,
    },
    Surface {
        name: "status_50",
        selector: 0x50,
        offset: 0,
        length: 16,
        chunk: 16,
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_reads_keep_wire_addresses_separate_from_host_offsets() {
        assert_eq!(
            CPU_ALIAS.read_cdb(0, 0x300),
            Some(crate::cdb::read_memory(0x880000, 0x300))
        );
        assert!(CPU_HIGH.read_cdb(0x2000, 1).is_none());
        assert!(CPU_HIGH.read_cdb(0, 0x101).is_none());
        assert!(CPU_LOW.read_cdb(usize::MAX, 1).is_none());
        assert!(CPU_LOW.read_cdb(0, 0).is_none());
        assert_eq!(
            LOG.read_cdb(0, LOG.length),
            Some(crate::cdb::diagnostic_log())
        );
    }
}
