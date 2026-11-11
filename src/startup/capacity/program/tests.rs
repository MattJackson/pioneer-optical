use super::*;

/// One build of a corpus-shaped discriminator: a flash-ID query through an
/// in-block builder and the resident service, a log call into Normal, then
/// the decision on the returned ID byte.
struct Build {
    /// RAM address of the copied block and of the entry inside it.
    block: u32,
    entry: u32,
    builder: u32,
    /// Normal offset of the log routine.
    logger: u32,
    handle: u32,
    global: u32,
}

const A: Build = Build {
    block: 0x5f0,
    entry: 0x600,
    builder: 0x640,
    logger: 0x100,
    handle: 0x0091_f480,
    global: 0x3328,
};
const B: Build = Build {
    block: 0x4b0,
    entry: 0x4ba,
    builder: 0x50a,
    logger: 0x2f0,
    handle: 0x0092_06e8,
    global: 0x33de,
};

fn be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

impl Build {
    fn entry_code(&self) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend([0x79, 0x37, 0x00, 0x08]); // SUB.W #8,R7
        c.extend([0x79, 0x00, 0x42, 0x90]); // MOV.W #4290,R0
        c.push(0x5e); // JSR builder
        c.extend(&be(self.builder)[1..]);
        c.extend([0x5e, 0x10, 0x7c, 0x72]); // JSR resident query
        c.extend([0x7a, 0x00]); // MOV.L #handle,ER0
        c.extend(be(self.handle));
        c.extend([0x01, 0x00, 0x69, 0xf0]); // MOV.L ER0,@ER7
        c.extend([0x1a, 0x80]); // SUB.L ER0,ER0
        c.push(0x5e); // JSR logger
        c.extend(&be(NORMAL_BASE + self.logger)[1..]);
        c.extend(self.decision());
        c
    }

    fn decision(&self) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend([0x7a, 0x01, 0xff, 0x3f, 0x00, 0x00]); // MOV.L #FF3F0000,ER1
        c.extend([0x6e, 0x18, 0x10, 0x18]); // MOV.B @(1018,ER1),R0L
        c.extend([0xa8, 0xef]); // CMP.B #EF,R0L
        c.extend([0x46, 0x04]); // BNE one
        c.extend([0x18, 0x88]); // SUB.B R0L,R0L
        c.extend([0x40, 0x02]); // BRA done
        c.extend([0xf8, 0x01]); // one: MOV.B #1,R0L
        c.extend([0x79, 0x17, 0x00, 0x08]); // done: ADD.W #8,R7
        c.extend([0x54, 0x70]); // RTS
        c
    }

    fn logger_code(&self) -> Vec<u8> {
        let mut c = vec![0x01, 0x00, 0x6b, 0x22]; // MOV.L @global,ER2
        c.extend(be(self.global));
        c.extend([0x54, 0x70]);
        c
    }

    fn images(&self, entry: &[u8], logger: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut ram = vec![0u8; self.block as usize + 0x110];
        let e = self.entry as usize;
        ram[e..e + entry.len()].copy_from_slice(entry);
        let b = self.builder as usize;
        ram[b..b + 2].copy_from_slice(&[0x54, 0x70]);
        let mut normal = vec![0u8; 0x400];
        let l = self.logger as usize;
        normal[l..l + logger.len()].copy_from_slice(logger);
        (ram, normal)
    }

    fn digest_of(&self, entry: &[u8], logger: &[u8]) -> Option<[u8; 32]> {
        let (ram, normal) = self.images(entry, logger);
        let sections = [Range {
            start: 0x2e00,
            end: 0x3500,
        }];
        Space {
            ram: &ram,
            block: self.block..self.block + 0x110,
            normal: &normal,
            sections: &sections,
        }
        .digest(self.entry)
    }

    fn digest(&self) -> Option<[u8; 32]> {
        self.digest_of(&self.entry_code(), &self.logger_code())
    }
}

fn replace(code: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = code.windows(from.len()).position(|w| w == from).unwrap();
    let mut out = code.to_vec();
    out[at..at + from.len()].copy_from_slice(to);
    out
}

#[test]
fn builds_differing_only_in_link_layout_digest_equally() {
    let a = A.digest().unwrap();
    assert_eq!(B.digest(), Some(a));
}

#[test]
fn the_query_the_decision_and_the_resident_service_are_exact() {
    let a = A.digest().unwrap();
    let code = A.entry_code();
    let logger = A.logger_code();
    for (from, to) in [
        (&[0x79, 0x00, 0x42, 0x90][..], &[0x79, 0x00, 0x42, 0x91][..]),
        (&[0xa8, 0xef], &[0xa8, 0xc2]),
        (&[0x5e, 0x10, 0x7c, 0x72], &[0x5e, 0x10, 0x7c, 0x80]),
        (&[0x7a, 0x01, 0xff, 0x3f], &[0x7a, 0x01, 0xff, 0x3e]),
    ] {
        let changed = A.digest_of(&replace(&code, from, to), &logger);
        assert!(changed.is_some_and(|d| d != a), "{to:02x?}");
    }
}

#[test]
fn a_different_side_implementation_still_relates() {
    let a = A.digest().unwrap();
    // The log routine reads a register instead of its global: side code is
    // verified, not compared, so the bank decision still relates.
    let other = [0x0f, 0x82, 0x00, 0x00, 0x00, 0x00, 0x54, 0x70];
    assert_eq!(A.digest_of(&A.entry_code(), &other), Some(a));
}

#[test]
fn side_code_that_writes_or_names_the_query_hardware_refuses() {
    let logger = A.logger_code();
    for insert in [
        // MOV.L ER2,@FF3F1018: writes the flash-ID register page.
        vec![0x01, 0x00, 0x6b, 0xa2, 0xff, 0x3f, 0x10, 0x18],
        // MOV.L #FF3F1018,ER0: names it, so a pointer write could reach it.
        vec![0x7a, 0x00, 0xff, 0x3f, 0x10, 0x18],
        // JSR @107C72: re-runs the query service.
        vec![0x5e, 0x10, 0x7c, 0x72],
    ] {
        let mut changed = logger.clone();
        changed.splice(8..8, insert.clone());
        assert_eq!(
            A.digest_of(&A.entry_code(), &changed),
            None,
            "{insert:02x?}"
        );
    }
    // On-chip I/O outside the query's pages (a UART, say) stays allowed.
    let mut uart = logger.clone();
    uart.splice(8..8, [0x01, 0x00, 0x6b, 0xa2, 0xff, 0xff, 0x00, 0x00]);
    assert!(A.digest_of(&A.entry_code(), &uart).is_some());
}

#[test]
fn a_side_argument_on_a_query_page_is_exact() {
    let at = |handle: u32| {
        let code = replace(&A.entry_code(), &be(A.handle), &be(handle));
        A.digest_of(&code, &A.logger_code()).unwrap()
    };
    assert_ne!(at(0xff3f_1018), at(0xff3f_1019));
    assert_eq!(at(0x0091_0000), at(0x0092_0000));
}

#[test]
fn a_side_call_before_the_query_refuses() {
    let code = A.entry_code();
    let resident = [0x5e, 0x10, 0x7c, 0x72];
    let mut logger_call = vec![0x5e];
    logger_call.extend(&be(NORMAL_BASE + A.logger)[1..]);
    let swapped = replace(
        &replace(&code, &logger_call, &[0; 4]),
        &resident,
        &logger_call,
    );
    let swapped = replace(&swapped, &[0; 4], &resident);
    assert_eq!(A.digest_of(&swapped, &A.logger_code()), None);
}

#[test]
fn side_argument_setup_may_only_store_to_the_stack() {
    // MOV.L ER0,@ER7 becomes MOV.L ER0,@00003000:32 (padded to length).
    let code = A.entry_code();
    let mut changed = replace(&code, &[0x01, 0x00, 0x69, 0xf0], &[0x01, 0x00, 0x6b, 0xa0]);
    let at = changed
        .windows(4)
        .position(|w| w == [0x01, 0x00, 0x6b, 0xa0])
        .unwrap();
    changed.splice(at + 4..at + 4, be(0x3000));
    assert_eq!(A.digest_of(&changed, &A.logger_code()), None);
}

#[test]
fn a_decision_that_reads_a_register_set_before_it_refuses() {
    // MOV.L #FF3F0000,ER1 becomes NOP; NOP; MOV.L ER2,ER1.
    let code = replace(
        &A.entry_code(),
        &[0x7a, 0x01, 0xff, 0x3f, 0x00, 0x00],
        &[0x00, 0x00, 0x00, 0x00, 0x0f, 0xa1],
    );
    assert_eq!(A.digest_of(&code, &A.logger_code()), None);
}

#[test]
fn an_entry_outside_the_block_refuses() {
    let (ram, normal) = A.images(&A.entry_code(), &A.logger_code());
    let space = Space {
        ram: &ram,
        block: A.block..A.block + 0x110,
        normal: &normal,
        sections: &[],
    };
    assert_eq!(space.digest(A.block + 0x200), None);
}
