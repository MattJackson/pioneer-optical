//! Generic H8 firmware facts. Does not allocate drive RAM or construct payloads.

/// Bounded symbolic analysis of memory-helper calling conventions.
pub mod abi {
    // Bounded symbolic tracing of OEM argument construction. Unknown instructions
    // are rejected. No model names, firmware revisions, or firmware addresses occur here.
    use anyhow::{bail, ensure, Context, Result};
    use std::collections::BTreeMap;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Byte {
        Unknown,
        Constant(u8),
        Object(u8),
        CdbPointer(u8),
        Cdb(u8),
    }
    type Value = [Byte; 4];
    const UNKNOWN: Value = [Byte::Unknown; 4];
    fn object() -> Value {
        std::array::from_fn(|i| Byte::Object(i as u8))
    }
    fn cdb_pointer() -> Value {
        std::array::from_fn(|i| Byte::CdbPointer(i as u8))
    }
    fn cdb24(first: u8) -> Value {
        [
            Byte::Constant(0),
            Byte::Cdb(first),
            Byte::Cdb(first + 1),
            Byte::Cdb(first + 2),
        ]
    }
    fn byte_location(r: u8) -> (usize, usize) {
        ((r & 7) as usize, if r & 8 == 0 { 2 } else { 3 })
    }
    fn word_location(r: u8) -> (usize, usize) {
        ((r & 7) as usize, if r & 8 == 0 { 2 } else { 0 })
    }
    fn u32be(b: &[u8]) -> u32 {
        u32::from_be_bytes(b[..4].try_into().unwrap())
    }
    fn offset(image: &[u8], base: u32, address: u32, n: usize) -> Result<&[u8]> {
        ensure!(address % 2 == 0, "unaligned H8 code target");
        let at = address
            .checked_sub(base)
            .context("code target below image")? as usize;
        image
            .get(at..at.checked_add(n).context("code range overflow")?)
            .context("code target outside image")
    }
    struct State {
        er: [Value; 8],
        stack: BTreeMap<i32, Byte>,
        sp: i32,
    }
    impl State {
        fn new() -> Self {
            let mut s = Self {
                er: [UNKNOWN; 8],
                stack: BTreeMap::new(),
                sp: 0,
            };
            s.er[0] = object();
            s.er[1] = cdb_pointer();
            s
        }
        fn get_byte(&self, r: u8) -> Byte {
            let (r, b) = byte_location(r);
            self.er[r][b]
        }
        fn set_byte(&mut self, r: u8, v: Byte) {
            let (r, b) = byte_location(r);
            self.er[r][b] = v;
        }
        fn load(&self, at: i32) -> Value {
            std::array::from_fn(|i| *self.stack.get(&(at + i as i32)).unwrap_or(&Byte::Unknown))
        }
        fn store(&mut self, at: i32, v: Value) {
            for (i, b) in v.into_iter().enumerate() {
                self.stack.insert(at + i as i32, b);
            }
        }
        fn push(&mut self, v: Value) {
            self.sp -= 4;
            self.store(self.sp, v);
        }
    }

    /// Follow CDB[2]'s dispatch and prove the helper arguments at the first call.
    /// ER0=object, R1L=direction, ER2=BE24(CDB[3..6]), stack=BE24(CDB[6..9]).
    /// Resolve a memory helper by tracing address, length and direction arguments.
    pub fn memory_call(
        image: &[u8],
        base: u32,
        main: u32,
        selector: u8,
        write: bool,
    ) -> Result<u32> {
        let mut state = State::new();
        let mut pc = main;
        let mut compare = None;
        let mut selected = false;
        for _ in 0..160 {
            let b = offset(image, base, pc, 2)?;
            let (op, arg) = (b[0], b[1]);
            let len = match (op, arg) {
                (0x01, 0x20) => {
                    let b = offset(image, base, pc, 4)?;
                    ensure!(
                        b[2] == 0x6d && b[3] & 0xf8 == 0xf0,
                        "unsupported register save"
                    );
                    let first = (b[3] & 7) as usize;
                    ensure!(first + 2 < 7, "unsupported saved registers");
                    for r in (first..first + 3).rev() {
                        state.push(state.er[r]);
                    }
                    4
                }
                (0x01, 0) => {
                    let b = offset(image, base, pc, 4)?;
                    let reg = (b[3] & 7) as usize;
                    match b[2] {
                        0x6d => {
                            ensure!(b[3] & 0xf8 == 0xf0, "unsupported stack operation");
                            state.push(state.er[reg]);
                            4
                        }
                        0x6f => {
                            let b = offset(image, base, pc, 6)?;
                            ensure!((b[3] >> 4) & 7 == 7, "non-stack long local");
                            let d = i16::from_be_bytes([b[4], b[5]]) as i32;
                            let at = state.sp + d;
                            if b[3] & 0x80 != 0 {
                                state.store(at, state.er[reg]);
                            } else {
                                state.er[reg] = state.load(at);
                            }
                            6
                        }
                        0x69 => {
                            ensure!(b[3] & 0xf8 == 0xf0, "unsupported stack argument store");
                            state.store(state.sp, state.er[reg]);
                            4
                        }
                        _ => bail!("unsupported long instruction at {pc:#x}"),
                    }
                }
                (0x79, 0x37) => {
                    let b = offset(image, base, pc, 4)?;
                    let n = u16::from_be_bytes([b[2], b[3]]);
                    ensure!(
                        n > 0 && n < 4096 && state.sp >= -32,
                        "unsupported stack frame"
                    );
                    state.sp -= n as i32;
                    4
                }
                (0x0f, _) => {
                    ensure!(arg & 0x88 == 0x80, "unsupported long register move");
                    state.er[(arg & 7) as usize] = state.er[((arg >> 4) & 7) as usize];
                    2
                }
                (0x0d, _) => {
                    let (sr, sb) = word_location(arg >> 4);
                    let (dr, db) = word_location(arg & 15);
                    let v = [state.er[sr][sb], state.er[sr][sb + 1]];
                    state.er[dr][db..db + 2].copy_from_slice(&v);
                    2
                }
                (0x0c, _) => {
                    state.set_byte(arg & 15, state.get_byte(arg >> 4));
                    2
                }
                (0x18, _) => {
                    ensure!(arg >> 4 == arg & 15, "unsupported byte subtraction");
                    state.set_byte(arg & 15, Byte::Constant(0));
                    2
                }
                (0xe0..=0xef, _) => {
                    let r = op & 15;
                    let v = match state.get_byte(r) {
                        Byte::Constant(v) => Byte::Constant(v & arg),
                        _ => Byte::Unknown,
                    };
                    state.set_byte(r, v);
                    2
                }
                (0xf0..=0xff, _) => {
                    state.set_byte(op & 15, Byte::Constant(arg));
                    2
                }
                (0x6e, _) => {
                    let b = offset(image, base, pc, 4)?;
                    let d = i16::from_be_bytes([b[2], b[3]]) as i32;
                    let base_reg = ((arg >> 4) & 7) as usize;
                    let r = arg & 15;
                    if arg & 0x80 != 0 {
                        ensure!(base_reg == 7, "non-stack byte store before helper");
                        state.stack.insert(state.sp + d, state.get_byte(r));
                    } else {
                        let value = if base_reg == 7 {
                            *state.stack.get(&(state.sp + d)).unwrap_or(&Byte::Unknown)
                        } else {
                            ensure!(
                                state.er[base_reg] == cdb_pointer() && (0..16).contains(&d),
                                "unproven CDB byte load"
                            );
                            Byte::Cdb(d as u8)
                        };
                        state.set_byte(r, value);
                    }
                    4
                }
                (0xa0..=0xaf, _) => {
                    ensure!(
                        state.get_byte(op & 15) == Byte::Cdb(2),
                        "dispatch comparison is not CDB selector"
                    );
                    compare = Some(arg == selector);
                    2
                }
                (0x58, 0x70) | (0x47, _) => {
                    let (taken, displacement, n) = if op == 0x58 {
                        let b = offset(image, base, pc, 4)?;
                        (compare.take(), i16::from_be_bytes([b[2], b[3]]) as i32, 4)
                    } else {
                        (compare.take(), arg as i8 as i32, 2)
                    };
                    let taken = taken.context("conditional branch without selector comparison")?;
                    if taken {
                        ensure!(!selected, "multiple selected dispatch branches");
                        selected = true;
                        pc = (pc as i64 + n + displacement as i64)
                            .try_into()
                            .context("branch target overflow")?;
                        continue;
                    }
                    n as usize
                }
                (0x5e, _) => {
                    ensure!(selected, "helper call before selecting memory command");
                    ensure!(
                        state.er[0] == object(),
                        "helper object argument is not the original object"
                    );
                    ensure!(
                        state.get_byte(9) == Byte::Constant(u8::from(write)),
                        "helper direction argument differs"
                    );
                    ensure!(
                        state.er[2] == cdb24(3),
                        "helper address is not the CDB 24-bit address"
                    );
                    ensure!(
                        state.load(state.sp) == cdb24(6),
                        "helper stack length is not the CDB 24-bit length"
                    );
                    let target = u32be(offset(image, base, pc, 4)?) & 0xffffff;
                    offset(image, base, target, 2)?;
                    return Ok(target);
                }
                _ => bail!("unsupported argument instruction {op:02x} {arg:02x} at {pc:#x}"),
            };
            pc = pc
                .checked_add(len as u32)
                .context("instruction address overflow")?;
        }
        bail!("memory helper trace exceeded instruction budget")
    }

    /// Validate both observed stack-save encodings by their ABI, and derive the
    /// invalid-field helper from the controller end-bound failure edge.
    /// Resolve the controller error target from a recognized memory helper.
    pub fn controller_error(image: &[u8], base: u32, helper: u32) -> Result<u32> {
        let h = offset(image, base, helper, 40)?;
        let (save, stack, restore) = if h[..2] == [0x6d, 0xf3] {
            (2, 14, &[0x6d, 0x73][..])
        } else {
            ensure!(h[..4] == [1, 0, 0x6d, 0xf3], "unknown helper save ABI");
            (4, 16, &[1, 0, 0x6d, 0x73][..])
        };
        let p = &h[save..];
        ensure!(
            p[..4] == [1, 0x20, 0x6d, 0xf4],
            "helper callee-save set differs"
        );
        ensure!(
            p[4] == 0x0f && p[5] & 0xf8 == 0xa0 && (3..=6).contains(&(p[5] & 7)),
            "helper address not saved in callee register"
        );
        ensure!(
            p[6] == 0x0c && p[7] >> 4 == 9 && (3..=6).contains(&(p[7] & 7)),
            "helper direction not saved in callee register"
        );
        ensure!(
            p[8..16] == [0x0f, 0x85, 0x0f, 0xa1, 1, 0, 0x6f, 0x76]
                && u16::from_be_bytes([p[16], p[17]]) == stack + 4,
            "helper stack argument ABI differs"
        );
        ensure!(
            p[18..28] == [0x0a, 0xe2, 0x0f, 0xa0, 0x7a, 0x22, 0, 0x40, 0, 0],
            "helper end-bound calculation differs"
        );
        let branch = helper + save as u32 + 28;
        let b = offset(image, base, branch, 4)?;
        let error = if b[..2] == [0x43, 8] {
            branch + 2
        } else {
            ensure!(b[..2] == [0x58, 0x20], "unsupported end-bound branch");
            (branch as i64 + 4 + i16::from_be_bytes([b[2], b[3]]) as i64)
                .try_into()
                .context("error branch overflow")?
        };
        let e = offset(image, base, error, 8)?;
        ensure!(e[0] == 0x5e, "bound failure does not call error helper");
        let invalid = u32be(e) & 0xffffff;
        let thunk = offset(image, base, invalid, 8)?;
        ensure!(
            thunk[..3] == [0xf8, 0xcc, 0x5e] && thunk[6..] == [0x54, 0x70],
            "invalid-field thunk differs"
        );
        offset(image, base, u32be(&thunk[2..6]) & 0xffffff, 2)?;
        let failure = if e[4] == 0x5a {
            u32be(&e[4..8]) & 0xffffff
        } else {
            error + 4
        };
        let tail = offset(image, base, failure, 2 + 4 + restore.len() + 2)?;
        ensure!(
            tail[..6] == [0xf8, 1, 1, 0x20, 0x6d, 0x76]
                && tail[6..6 + restore.len()] == *restore
                && tail[6 + restore.len()..] == [0x54, 0x70],
            "helper error return does not restore its ABI frame"
        );
        Ok(invalid)
    }

    #[cfg(test)]
    mod tests {
        include!("firmware_abi_tests.rs");
    }
}

/// Structural memory layout inspection.
pub mod layout {
    use anyhow::{ensure, Result};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    /// Half-open CPU address interval.
    pub struct Range {
        /// Inclusive CPU start address.
        pub start: u32,
        /// Exclusive CPU end address.
        pub end: u32,
    }

    impl Range {
        /// Construct a nonempty interval with checked arithmetic.
        pub fn new(start: u32, length: u32) -> Result<Self> {
            ensure!(length > 0, "empty range");
            let end = start
                .checked_add(length)
                .ok_or_else(|| anyhow::anyhow!("range overflow"))?;
            Ok(Self { start, end })
        }

        /// Whether two intervals intersect.
        pub fn overlaps(&self, other: &Self) -> bool {
            self.start < other.end && other.start < self.end
        }

        /// Whether this interval contains the other.
        pub fn contains(&self, other: &Self) -> bool {
            self.start <= other.start && other.end <= self.end
        }
    }

    #[derive(Clone, Debug, Serialize)]
    /// One recognized OEM buffer descriptor.
    pub struct BufferEntry {
        /// OEM buffer identifier.
        pub id: u8,
        /// Controller-relative start, or the OEM sentinel.
        pub controller_start: u32,
        /// Length in bytes, or the OEM sentinel.
        pub length: u32,
    }

    #[derive(Clone, Debug, Serialize)]
    /// An OEM buffer table and the code references supporting its identification.
    pub struct BufferTable {
        /// Byte offset in the decoded image.
        pub image_offset: usize,
        /// Instruction offsets referencing this table.
        pub reference_offsets: Vec<usize>,
        /// Decoded descriptors.
        pub entries: Vec<BufferEntry>,
    }

    #[derive(Clone, Debug, Serialize)]
    /// Structural firmware memory facts; gaps are not runtime allocation guarantees.
    pub struct Layout {
        /// Whether the image has a recognized UHD layout.
        pub is_uhd: bool,
        /// Decoded image CPU base.
        pub image_base: Option<u32>,
        /// Recognized overlay destination intervals.
        pub overlay_ranges: Vec<Range>,
        /// Recognized OEM buffer maps.
        pub buffer_tables: Vec<BufferTable>,
        /// Aligned end of recognized overlays.
        pub overlay_tail: Option<u32>,
        /// OEM buffers overlapping the illustrative overlay-tail interval.
        pub tail_buffer_conflicts: Vec<Range>,
        /// Limitations of the structural findings.
        pub limitations: Vec<String>,
        /// Global-data canary addresses initialized by firmware.
        pub global_canaries: Vec<u32>,
        /// Intervals between recognized global data and OEM buffers.
        pub structural_gaps: Vec<Range>,
        /// End address of the corroborated global-data copy.
        pub global_copy_end: Option<u32>,
    }

    fn be32(b: &[u8]) -> u32 {
        u32::from_be_bytes(b[..4].try_into().expect("bounded slice"))
    }

    fn table(image: &[u8], offset: usize) -> Option<Vec<BufferEntry>> {
        let mut rows = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for n in 0..128 {
            let row = image.get(offset.checked_add(n * 12)?..offset.checked_add((n + 1) * 12)?)?;
            if row
                == [
                    0xff, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ]
            {
                return (rows.len() >= 2).then_some(rows);
            }
            if row[0] > 0x7f || row[1] != 0 || !ids.insert(row[0]) {
                return None;
            }
            let start = be32(&row[4..]);
            let length = be32(&row[8..]);
            if start != u32::MAX && start >= 0x400000 {
                return None;
            }
            if length != u32::MAX && (length == 0 || length > 0x400000) {
                return None;
            }
            if start != u32::MAX && length != u32::MAX && start.checked_add(length)? > 0x400000 {
                return None;
            }
            rows.push(BufferEntry {
                id: row[0],
                controller_start: start,
                length,
            });
        }
        None
    }

    /// Recognize layout evidence in a decoded body. This does not prove free RAM.
    pub fn inspect(image: &[u8]) -> Result<Layout> {
        let mut out = Layout {
            is_uhd: crate::image::is_uhd(image),
            image_base: None,
            overlay_ranges: vec![],
            buffer_tables: vec![],
            overlay_tail: None,
            tail_buffer_conflicts: vec![],
            limitations: vec![],
            global_canaries: vec![],
            structural_gaps: vec![],
            global_copy_end: None,
        };
        if !out.is_uhd {
            out.limitations
                .push("Excluded: pioneer-optical is_uhd is false".into());
            return Ok(out);
        }
        let Some((base, streams)) = crate::envelope::comp_streams(image) else {
            out.limitations.push("No supported COMP layout".into());
            return Ok(out);
        };
        out.image_base = Some(base);
        for (off, w) in image.windows(36).enumerate() {
            if w[..3] != [0xa8, 3, 0x47]
                || w[4..7] != [0xa8, 4, 0x47]
                || w[8..12] != [0xa8, 5, 0x58, 0x60]
                || w[14..16] != [0x7a, 4]
                || w[20] != 0x40
                || w[22..24] != [0x7a, 4]
                || w[28] != 0x40
                || w[30..32] != [0x7a, 4]
                || off % 2 != 0
            {
                continue;
            }
            for (index, pos) in [(5, 16), (4, 24), (3, 32)] {
                if let Some(stream) = streams.get(index) {
                    out.overlay_ranges.push(Range::new(
                        be32(&w[pos..]),
                        stream.expanded.len().try_into()?,
                    )?);
                }
            }
        }
        out.overlay_ranges.sort_by_key(|r| r.start);
        out.overlay_ranges.dedup();
        if let Some(last) = out.overlay_ranges.last() {
            out.overlay_tail = last.end.checked_add(31).map(|n| n & !31);
        }
        let mut found = std::collections::BTreeMap::<usize, BufferTable>::new();
        for (off, w) in image.windows(6).enumerate() {
            if off % 2 != 0 || w[0] != 0x7a || ![0x00, 0x10, 0x11].contains(&w[1]) {
                continue;
            }
            let Some(relative) = be32(&w[2..]).checked_sub(base) else {
                continue;
            };
            let relative = relative as usize;
            if let Some(entries) = table(image, relative) {
                found
                    .entry(relative)
                    .or_insert_with(|| BufferTable {
                        image_offset: relative,
                        reference_offsets: vec![],
                        entries,
                    })
                    .reference_offsets
                    .push(off);
            }
        }
        out.buffer_tables = found.into_values().collect();
        let mut canary_groups = Vec::new();
        for (off, w) in image.windows(4).enumerate() {
            if off % 2 != 0 || w != [0x79, 1, 0xa5, 0xa5] {
                continue;
            }
            let mut at = off + 4;
            let mut group = Vec::new();
            while let Some(store) = image.get(at..at + 6) {
                if store[..2] != [0x6b, 0xa1] {
                    break;
                }
                let addr = be32(&store[2..]);
                if (0xa00000..0xa10000).contains(&addr) {
                    group.push(addr);
                }
                at += 6;
            }
            if !group.is_empty() {
                canary_groups.push(group);
            }
        }
        if canary_groups.len() == 1 {
            out.global_canaries = canary_groups.remove(0);
            let last = *out.global_canaries.iter().max().expect("nonempty group");
            for (off, w) in image.windows(18).enumerate() {
                if off % 2 != 0
                    || w[..2] != [0x7a, 0]
                    || w[6..8] != [0x7a, 1]
                    || w[12..14] != [0x7a, 2]
                {
                    continue;
                }
                let source = be32(&w[2..]);
                let stop = be32(&w[8..]);
                let dest = be32(&w[14..]);
                if source >= base
                    && stop > source
                    && stop <= base + image.len() as u32
                    && (0xa00000..0xa10000).contains(&dest)
                    && dest.checked_add(stop - source) == Some(last)
                {
                    out.global_copy_end = Some(last);
                }
            }
            let first_buffer = out
                .buffer_tables
                .iter()
                .flat_map(|t| &t.entries)
                .filter(|e| e.controller_start != u32::MAX && e.length != u32::MAX)
                .map(|e| 0xa00000 + e.controller_start)
                .min();
            if let Some(end) = first_buffer {
                let start = (last + 2 + 31) & !31;
                if start < end && out.global_copy_end == Some(last) {
                    out.structural_gaps.push(Range { start, end });
                }
            }
        }
        if let Some(start) = out.overlay_tail {
            let candidate = Range::new(start, 512)?;
            for t in &out.buffer_tables {
                for e in &t.entries {
                    if e.controller_start == u32::MAX || e.length == u32::MAX {
                        continue;
                    }
                    let r = Range::new(0xa00000 + e.controller_start, e.length)?;
                    if r.overlaps(&candidate) && !out.tail_buffer_conflicts.contains(&r) {
                        out.tail_buffer_conflicts.push(r);
                    }
                }
            }
        }
        out.limitations.push("Structural gaps are bounded by a copied-data end canary and the first OEM buffer; runtime canaries and stability must be checked. This is not a guarantee against every indirect/DMA access.".into());
        Ok(out)
    }

    /// Subtract occupied intervals and align the resulting structural gaps.
    pub fn free_ranges(
        windows: &[Range],
        occupied: &[Range],
        alignment: u32,
    ) -> Result<Vec<Range>> {
        ensure!(
            alignment.is_power_of_two() && alignment >= 2,
            "invalid alignment"
        );
        ensure!(
            windows.iter().chain(occupied).all(|r| r.start < r.end),
            "invalid map interval"
        );
        let mut windows = windows.to_vec();
        windows.sort_by_key(|r| r.start);
        let mut merged: Vec<Range> = vec![];
        for window in windows {
            if let Some(last) = merged.last_mut() {
                if window.start <= last.end {
                    last.end = last.end.max(window.end);
                    continue;
                }
            }
            merged.push(window);
        }
        let mut blocks = occupied.to_vec();
        blocks.sort_by_key(|r| r.start);
        let mut result = Vec::new();
        for window in merged {
            let mut cursor = window.start;
            for block in blocks.iter().filter(|b| b.overlaps(&window)) {
                if let Some(start) = cursor
                    .checked_add(alignment - 1)
                    .map(|v| v & !(alignment - 1))
                    .filter(|start| *start < block.start.min(window.end))
                {
                    result.push(Range {
                        start,
                        end: block.start.min(window.end),
                    });
                }
                cursor = cursor.max(block.end);
            }
            if let Some(start) = cursor
                .checked_add(alignment - 1)
                .map(|v| v & !(alignment - 1))
                .filter(|start| *start < window.end)
            {
                result.push(Range {
                    start,
                    end: window.end,
                });
            }
        }
        Ok(result)
    }
}

/// Opcode registry and callback initialization inspection.
pub mod callbacks {
    use anyhow::{ensure, Context, Result};
    use serde::Serialize;
    fn word(bytes: &[u8]) -> u32 {
        u32::from_be_bytes(bytes[..4].try_into().expect("bounded slice"))
    }

    #[derive(Debug, Clone, Serialize)]
    /// Dispatch registry, object and callback facts recovered from initialization code.
    pub struct OpcodeSite {
        /// Opcode registry CPU address.
        pub opcode_table: u32,
        /// Dispatch object CPU address.
        pub object: u32,
        /// Initialized callback table CPU address.
        pub table: u32,
        /// Main callback code address.
        pub main: u32,
    }

    /// Locate the opcode registry, then follow the READ BUFFER object's initializer.
    pub fn read_buffer_site(image: &[u8], base: u32) -> Result<OpcodeSite> {
        opcode_site(image, base, 0x3c)
    }

    /// Locate an opcode object and its initialized callback table.
    pub fn opcode_site(image: &[u8], base: u32, opcode: usize) -> Result<OpcodeSite> {
        ensure!(opcode < 64, "opcode outside recognized registry");
        let mut registries = Vec::new();
        for (off, window) in image.windows(256).enumerate() {
            if off % 2 != 0
                || word(window) == 0
                || word(window) >= 0x8000
                || word(&window[8..]) != 0
            {
                continue;
            }
            let slots: Vec<u32> = window.chunks_exact(4).map(word).collect();
            if slots.iter().filter(|v| **v == 0).count() < 30
                || slots.iter().any(|v| *v >= 0x8000)
                || [0, 1, 3, 4, 0x12, 0x3b, 0x3c]
                    .iter()
                    .any(|i| slots[*i] == 0)
            {
                continue;
            }
            registries.push((off, slots[opcode]));
        }
        ensure!(
            registries.len() == 1,
            "opcode registry absent/ambiguous ({})",
            registries.len()
        );
        let (registry, object) = registries[0];
        let mut tables = Vec::new();
        for (off, w) in image.windows(14).enumerate() {
            if off % 2 == 0
                && w[..2] == [0x7a, 1]
                && w[6..10] == [1, 0, 0x6b, 0xa1]
                && word(&w[10..]) == object
            {
                tables.push(word(&w[2..]));
            }
        }
        ensure!(tables.len() == 1, "object initializer absent/ambiguous");
        let table = tables[0];
        let offset = table.checked_sub(base).context("table outside image")? as usize;
        let bytes = image
            .get(offset..offset + 40)
            .context("truncated callback table")?;
        ensure!(
            bytes[0x14..0x18] == [0; 4] && bytes[0x1e..0x22] == [0; 4],
            "unsupported object adjustments"
        );
        let check = word(&bytes[0x10..])
            .checked_sub(base)
            .context("check outside image")? as usize;
        ensure!(
            opcode != 0x3c || image.get(check..check + 2) == Some(&[0x54, 0x70]),
            "unsupported check callback"
        );
        let main = word(&bytes[0x24..]);
        ensure!(
            main % 2 == 0 && main >= base && main < base + image.len() as u32,
            "callback outside Normal image"
        );
        let prep = word(&bytes[0x1a..])
            .checked_sub(base)
            .context("prepare outside image")? as usize;
        ensure!(
            opcode != 0x3c || image.get(prep..prep + 4) == Some(&[0x18, 0x88, 0x54, 0x70]),
            "unsupported preparation callback"
        );
        Ok(OpcodeSite {
            opcode_table: base + registry as u32,
            object,
            table,
            main,
        })
    }
}
