//! Numerical execution evidence for the complete bound five-word block primitive.
use super::*;

const IV: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
// Independent specification: eighty rounds over sixteen big-endian input words,
// expanded by xor/rotate, with the four SHA-1 Boolean functions and constants.
fn reference(state: [u32; 5], block: &[u8; 64]) -> [u32; 5] {
    let mut words = [0u32; 80];
    for (word, bytes) in words.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().unwrap());
    }
    for i in 16..80 {
        words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = state;
    for (i, word) in words.into_iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5a827999u32),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }
    let mut result = [a, b, c, d, e];
    for (out, old) in result.iter_mut().zip(state) {
        *out = out.wrapping_add(old);
    }
    result
}
fn machine() -> (Cpu, u32, u32) {
    let bodies = super::super::super::comp_code::primitive_bodies();
    let mut cpu = Cpu {
        mem: vec![0xa5; 0x1000000],
        initialized: vec![false; 0x1000000],
        output_end: OUTPUT + 20,
        stack: STACK - 132..STACK,
        scratch: 0..0,
        length: 0..0,
        r: [0; 8],
        known: [u32::MAX; 8],
        zn_known: true,
        z: false,
        n: false,
        v: false,
        c: false,
        code: BTreeMap::new(),
        frames: Vec::new(),
        free_calls: 0,
        free: u32::MAX,
        entries: [u32::MAX; 3],
        fault: Cell::new(false),
    };
    for (entry, body) in bodies {
        let mut offset = 0;
        while offset < body.len() {
            let d = decode_insn(&body[offset..], Target::H8S2000, Mode::Advanced).unwrap();
            assert!(
                !matches!(d.insn.mnemonic, "JSR" | "BSR"),
                "pure primitive must have no calls"
            );
            cpu.code.insert(entry + offset as u32, (d.insn, d.len));
            offset += d.len;
        }
    }
    (cpu, bodies[0].0, bodies[1].0)
}
fn invoke(cpu: &mut Cpu, entry: u32, flags: bool) {
    let initial = [
        OUTPUT, INPUT, 0x2468ace0, 0x13579bdf, 0x89abcdef, 0xfedcba98, 0x76543210, STACK,
    ];
    cpu.r = initial;
    cpu.known.fill(u32::MAX);
    cpu.z = flags;
    cpu.n = flags;
    cpu.v = flags;
    cpu.c = flags;
    cpu.zn_known = true;
    cpu.initialized[cpu.stack.start as usize..cpu.stack.end as usize].fill(false);
    cpu.mem[cpu.stack.start as usize..cpu.stack.end as usize].fill(if flags { 0xff } else { 0 });
    cpu.fault.set(false);
    cpu.push(0);
    let mut budget = 100_000;
    assert_eq!(cpu.run(entry, &mut budget), Some(()), "entry {entry:x}");
    assert!(!cpu.fault.get());
    assert!(cpu.frames.is_empty());
    assert_eq!(cpu.r[7], STACK);
    assert_eq!(&cpu.r[3..7], &initial[3..7], "ER3..ER6 preserved");
    assert!(cpu.initialized[OUTPUT as usize..OUTPUT as usize + 20]
        .iter()
        .all(|v| *v));
}
fn state(cpu: &Cpu) -> [u32; 5] {
    core::array::from_fn(|i| cpu.load(OUTPUT + i as u32 * 4, Size::Long))
}

#[test]
fn exact_native_initializer_and_eighty_round_block_transform() {
    let (mut cpu, transform, initializer) = machine();
    // Initializer must define exactly the five-word context without requiring
    // prior RAM or input state. Only twenty output bytes and its stack are writable.
    invoke(&mut cpu, initializer, false);
    assert_eq!(state(&cpu), IV);
    let mut abc = [0u8; 64];
    abc[..4].copy_from_slice(&[b'a', b'b', b'c', 0x80]);
    abc[63] = 24;
    assert_eq!(
        reference(IV, &abc),
        [0xa9993e36, 0x4706816a, 0xba3e2571, 0x7850c26c, 0x9cd0d89d]
    );
    let mut random = 0x9e3779b9u32;
    let mut next = || {
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        random
    };
    for case in 0..260 {
        let input_state = match case {
            0 => IV,
            1 => [0; 5],
            2 => [u32::MAX; 5],
            _ => core::array::from_fn(|_| next()),
        };
        let block = match case {
            0 => abc,
            1 => [0; 64],
            2 => [255; 64],
            3 => core::array::from_fn(|i| i as u8),
            _ => core::array::from_fn(|_| next() as u8),
        };
        for (i, word) in input_state.into_iter().enumerate() {
            cpu.store(OUTPUT + i as u32 * 4, Size::Long, word);
        }
        cpu.mem[INPUT as usize..INPUT as usize + 64].copy_from_slice(&block);
        cpu.initialized[INPUT as usize..INPUT as usize + 64].fill(true);
        invoke(&mut cpu, transform, case % 2 == 0);
        assert_eq!(state(&cpu), reference(input_state, &block), "case {case}");
        assert_eq!(
            &cpu.mem[INPUT as usize..INPUT as usize + 64],
            &block,
            "input unchanged"
        );
    }
}
