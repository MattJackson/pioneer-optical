//! Mapped diagnostic read surfaces. Support varies by firmware; callers must
//! retain refusal/short-read status rather than treating zero fill as real data.

const FIELD_MAX: usize = 0xff_ffff;
const MEMORY_CHUNK: usize = 0x1000;

/// A bounded vendor read surface, independent of any host dump-file layout.
#[derive(Clone, Copy, Debug)]
pub struct ReadSurface {
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
impl ReadSurface {
    /// Encode a bounded chunk, or return `None` for invalid ranges.
    pub fn read_cdb(self, offset: usize, length: usize) -> Option<[u8; 10]> {
        if length == 0 || length > self.chunk || offset.checked_add(length)? > self.length {
            return None;
        }
        let address = self.offset.checked_add(u32::try_from(offset).ok()?)?;
        if address as usize > FIELD_MAX || (address as usize).checked_add(length)? > FIELD_MAX + 1 {
            return None;
        }
        Some(crate::cdb::read_diagnostic(
            self.selector,
            address,
            length as u32,
        ))
    }
}
/// CPU memory before B0's high-register alias.
pub const CPU_LOW: ReadSurface = ReadSurface {
    name: "low_memory",
    selector: crate::cdb::MEMORY_ID,
    offset: 0,
    length: 0x880000,
    chunk: MEMORY_CHUNK,
};
/// CPU registers at FFFFE000..FFFFFFFF, addressed through selector 92.
pub const CPU_HIGH: ReadSurface = ReadSurface {
    name: "high_registers",
    selector: 0x92,
    offset: 0,
    length: 0x2000,
    chunk: 0x100,
};
/// CPU registers at FF414000..FF4142FF, reached through B0's alias.
pub const CPU_ALIAS: ReadSurface = ReadSurface {
    name: "high_register_alias",
    selector: crate::cdb::MEMORY_ID,
    offset: 0x880000,
    length: 0x300,
    chunk: 0x300,
};
/// Controller-local address space, distinct from CPU addresses.
pub const CONTROLLER: ReadSurface = ReadSurface {
    name: "controller_memory",
    selector: 0x93,
    offset: 0,
    length: 0x400000,
    chunk: MEMORY_CHUNK,
};
/// Exact diagnostic ring response in firmware-returned order.
pub const LOG: ReadSurface = ReadSurface {
    name: "diagnostic_log",
    selector: crate::cdb::DIAGNOSTIC_LOG_ID,
    offset: 0,
    length: crate::cdb::DIAGNOSTIC_LOG_LEN as usize,
    chunk: crate::cdb::DIAGNOSTIC_LOG_LEN as usize,
};

/// Mapped fixed diagnostic responses. These issue reads only; they do not
/// include poorly understood indexed or polling operations. FE temporarily
/// overrides the firmware's read gate and restores it before returning.
pub const RESPONSES: &[ReadSurface] = &[
    ReadSurface {
        name: "parameters",
        selector: 0xa0,
        offset: 0,
        length: 0x800,
        chunk: 0x800,
    },
    ReadSurface {
        name: "peripheral_e900",
        selector: 0xd0,
        offset: 0,
        length: 0x100,
        chunk: 0x100,
    },
    ReadSurface {
        name: "identity",
        selector: crate::cdb::IDENTITY_ID,
        offset: 0,
        length: 0x30,
        chunk: 0x30,
    },
    ReadSurface {
        name: "status_e0",
        selector: 0xe0,
        offset: 0,
        length: 0x20,
        chunk: 0x20,
    },
    ReadSurface {
        name: "status_e1",
        selector: 0xe1,
        offset: 0,
        length: 0x20,
        chunk: 0x20,
    },
    ReadSurface {
        name: "status_e5",
        selector: 0xe5,
        offset: 0,
        length: 2,
        chunk: 2,
    },
    ReadSurface {
        name: "status_e7",
        selector: 0xe7,
        offset: 0,
        length: 0x50,
        chunk: 0x50,
    },
    ReadSurface {
        name: "status_e6_03",
        selector: 0xe6,
        offset: 3,
        length: 4,
        chunk: 4,
    },
    ReadSurface {
        name: "bank_window",
        selector: 0xfe,
        offset: 0,
        length: 0x4000,
        chunk: 0x4000,
    },
    ReadSurface {
        name: "record_a",
        selector: 0xa4,
        offset: 0,
        length: 0x114,
        chunk: 0x114,
    },
    ReadSurface {
        name: "record_b",
        selector: 0xa8,
        offset: 0,
        length: 0x164,
        chunk: 0x164,
    },
    ReadSurface {
        name: "status_50",
        selector: 0x50,
        offset: 0,
        length: 16,
        chunk: 16,
    },
];

#[cfg(test)]
#[path = "diagnostic_tests.rs"]
mod tests;
