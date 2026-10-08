use super::*;

const PAYLOAD: usize = 0x10200;
const LEN: usize = 0x50000;

// A synthetic Normal image: low-entropy "code", a COMP directory, and two
// zlib streams at the end placed so the last Adler-32 trailer straddles the
// 48 bytes a three-block splice pushes out of the envelope (as in 8291).
pub(super) fn image() -> Vec<u8> {
    image_with(-1)
}

// `end2_delta` places the final Adler-32 trailer relative to the end of the
// carried bytes: -1 straddles the cut (as in 8291); a positive value pushes
// deflate bytes of the final stream into the lost tail (as in 8211).
fn image_with(end2_delta: isize) -> Vec<u8> {
    let mut image = vec![0u8; LEN];
    let mut state = 0x1234_5678u32;
    for byte in image.iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        *byte = [0x00, 0x01, 0x6a, 0x79, 0x0f, 0x5e, 0xff, 0x18][(state >> 28) as usize & 7];
    }
    image[..16].copy_from_slice(b"PIONEER BDR-TEST");
    image[20..24].copy_from_slice(&(LEN as u32).to_be_bytes());
    let base = 0x0041_0000u32;
    let zlib = |data: &[u8]| {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    };
    let first: Vec<u8> = (0..0x3000u32).map(|i| (i % 251) as u8).collect();
    let second: Vec<u8> = (0..0x2000u32).map(|i| (i * 7 % 13) as u8).collect();
    let (z1, z2) = (zlib(&first), zlib(&second));
    let kept_len = LEN - 3 * SPLICE_LEN;
    let end2 = (kept_len as isize + end2_delta) as usize; // default: 1 carried, 3 lost
    let start2 = end2 - z2.len();
    let start1 = (start2 - 0x40 - 4 - z1.len()) & !3;
    let end1 = start1 + z1.len();
    image[end2 + 4..].fill(0xff);
    image[end1 + 4..start2].fill(0xff);
    image[start1..start1 + 4].copy_from_slice(&(first.len() as u32).to_be_bytes());
    image[start1 + 4..end1 + 4].copy_from_slice(&z1);
    image[start2..start2 + 4].copy_from_slice(&(second.len() as u32).to_be_bytes());
    image[start2 + 4..end2 + 4].copy_from_slice(&z2);
    image[0x1000..0x1100].fill(0xff);
    image[0x1000..0x1004].copy_from_slice(b"COMP");
    for (i, v) in [start1, end1, start2, end2].into_iter().enumerate() {
        image[0x1004 + 4 * i..0x1008 + 4 * i].copy_from_slice(&(base + v as u32).to_be_bytes());
    }
    assert!(comp_streams(&image).is_some());
    image
}

// Encrypt as the OEM envelope does, then splice blocks at three of the four
// 64 KiB file boundaries and keep the declared file length.
pub(super) fn envelope(image: &[u8], at: &[usize]) -> Vec<u8> {
    let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   BDR-TEST\r\nRevision Level : 1.00\r\nFile Type : Normal\r\n";
    let mut out = vec![0u8; 0x200];
    out[..banner.len()].copy_from_slice(banner);
    let key = make_key(0x9272c0, 0x10000);
    out.extend_from_slice(&key);
    let cipher = transform(image, &key, true).unwrap();
    let mut payload = Vec::new();
    for (i, word) in cipher.chunks_exact(4).enumerate() {
        if at.contains(&(i * 4)) {
            payload.extend((0..16u8).map(|b| b.wrapping_mul(37) ^ (i as u8)));
        }
        payload.extend_from_slice(word);
    }
    payload.truncate(image.len());
    out.extend_from_slice(&payload);
    out
}

#[test]
fn spliced_normal_decodes_and_repacks_exactly() {
    let image = image();
    let at = [0xfe00, 0x2fe00, 0x3fe00];
    for &c in &at {
        assert_eq!((PAYLOAD + c) % SPLICE_ALIGN, 0);
    }
    let envelope = envelope(&image, &at);
    let decoded = decode_envelope(&envelope).unwrap();
    assert_eq!(decoded.info.layout, Layout::Normal);
    let found: Vec<usize> = decoded
        .spliced_blocks()
        .iter()
        .map(|s| s.image_offset)
        .collect();
    assert_eq!(found, at);
    // The three lost Adler-32 bytes are recomputed; padding is erased.
    assert_eq!(decoded.image, image);
    assert!(decoded.unrecovered_tail().is_none());
    assert_eq!(decoded.repack(&decoded.image).unwrap(), envelope);
    // A carried-byte edit re-encrypts in place around the blocks.
    let mut edited = decoded.image.clone();
    edited[0x30000] ^= 0x5a;
    let repacked = decoded.repack(&edited).unwrap();
    assert_eq!(decode_envelope(&repacked).unwrap().image, edited);
    // The envelope cannot carry the tail, so a tail edit is refused.
    let mut tail = decoded.image.clone();
    *tail.last_mut().unwrap() = 0;
    assert!(decoded.repack(&tail).is_none());
    assert!(decoded.repack_resized_normal(&decoded.image).is_none());
}

#[test]
fn unspliced_normal_is_untouched_and_bad_splices_fall_back() {
    let image = image();
    let plain = envelope(&image, &[]);
    let decoded = decode_envelope(&plain).unwrap();
    assert!(decoded.spliced_blocks().is_empty());
    assert_eq!(decoded.image, image);
    // A block off the 64 KiB grid is not a recognized splice: the ordinary
    // decode stands (garbage after the block), never a spliced guess.
    let off_grid = envelope(&image, &[0x20000]);
    let decoded = decode_envelope(&off_grid).unwrap();
    assert!(decoded.spliced_blocks().is_empty());
    assert_eq!(decoded.image[..0x20000], image[..0x20000]);
    assert_ne!(decoded.image[0x20010..], image[0x20000..LEN - 16]);
}

fn splice_key() -> Vec<u8> {
    make_key(0x9272c0, 0x10000)
}

const SPLICES: [usize; 3] = [0xfe00, 0x2fe00, 0x3fe00];
const KEPT: usize = LEN - 3 * SPLICE_LEN;

fn low_entropy(len: usize) -> Vec<u8> {
    let mut state = 0x0bad_cafeu32;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            [0x00, 0x01, 0x6a, 0x79, 0x0f, 0x5e, 0xff, 0x18][(state >> 28) as usize & 7]
        })
        .collect()
}

#[test]
fn find_splices_window_must_fit_exactly() {
    // Boundary at image offset 0x2000 (payload offset 0xe000 -> next 64 KiB
    // boundary 0x2000). The window after the block ends exactly at the end
    // of the ciphertext, which is still accepted; one word less is not.
    let key = make_key(0x123456, 0x1000);
    let plain = low_entropy(0x3000);
    let cipher = transform(&plain, &key, true).unwrap();
    let mut spliced = cipher[..0x2000].to_vec();
    spliced.extend((0..16u8).map(|b| b.wrapping_mul(37) ^ 0x5c));
    spliced.extend_from_slice(&cipher[0x2000..]);
    assert_eq!(spliced.len(), 0x3010);
    let found = find_splices(&spliced, 0xe000, &key, false);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].image_offset, 0x2000);
    assert_eq!(found[0].bytes[..], spliced[0x2000..0x2010]);
    // Four bytes short of a full skipped window: nothing is detected.
    assert!(find_splices(&spliced[..0x300c], 0xe000, &key, false).is_empty());
    // A misaligned payload offset cannot sit on a word boundary: no splices.
    assert!(find_splices(&spliced, 0xe002, &key, false).is_empty());
    // No usable key: no splices.
    assert!(find_splices(&spliced, 0xe000, &[], false).is_empty());
}

#[test]
fn key_words_requires_a_nonempty_word_aligned_key() {
    assert_eq!(key_words(&[]), None);
    assert_eq!(key_words(&[1, 2, 3, 4, 5]), None);
    assert_eq!(key_words(&[1, 2, 3]), None);
    assert_eq!(
        key_words(&[1, 0, 0, 0, 0, 0, 0, 0x80]),
        Some(vec![1, 0x8000_0000])
    );
}

#[test]
fn spliced_normal_validation_is_exact() {
    let key = splice_key();
    let run = |image: &[u8]| {
        let env = envelope(image, &SPLICES);
        spliced_normal(&env[PAYLOAD..], PAYLOAD, &key, false)
    };
    let good = image();
    let (decoded, splices) = run(&good).unwrap();
    assert_eq!(decoded, good);
    assert_eq!(splices.len(), 3);

    // The image must start with the Pioneer banner...
    let mut bad = good.clone();
    bad[0] = b'X';
    assert!(run(&bad).is_none());
    // ...and declare exactly its own length.
    let mut bad = good.clone();
    bad[20..24].copy_from_slice(&(LEN as u32 - 0x100).to_be_bytes());
    assert!(run(&bad).is_none());

    // A COMP image whose streams do not inflate is refused.
    let mut bad = good.clone();
    let start1 = u32::from_be_bytes(good[0x1004..0x1008].try_into().unwrap()) - 0x0041_0000;
    bad[start1 as usize + 4] = 0;
    assert!(comp_streams(&bad).is_none());
    assert!(run(&bad).is_none());

    // An image without a COMP directory has nothing further to validate.
    let mut plain = good.clone();
    plain[0x1000..0x1004].copy_from_slice(b"ZZZZ");
    plain[KEPT..].fill(0xff);
    let (decoded, _) = run(&plain).unwrap();
    assert_eq!(decoded, plain);

    // The final stream may reach into the lost tail (8211): accepted
    // although the padded image's COMP directory no longer inflates.
    let truncated = image_with(8);
    let (decoded, _) = run(&truncated).unwrap();
    let mut expected = truncated.clone();
    expected[KEPT..].fill(0xff);
    assert_eq!(decoded, expected);
    assert!(comp_streams(&decoded).is_none());
}

#[test]
fn unrecovered_tail_reports_exactly_the_unproven_range() {
    let tail = KEPT..LEN;
    // Fully verified COMP image: nothing unrecovered.
    let env = envelope(&image(), &SPLICES);
    assert_eq!(decode_envelope(&env).unwrap().unrecovered_tail(), None);

    // Final stream truncated: the whole carried-less tail is reported even
    // though a COMP directory is present.
    let truncated = image_with(8);
    let env = envelope(&truncated, &SPLICES);
    let decoded = decode_envelope(&env).unwrap();
    assert_eq!(decoded.spliced_blocks().len(), 3);
    assert_eq!(decoded.unrecovered_tail(), Some(tail.clone()));
    assert_eq!(decoded.repack(&decoded.image).unwrap(), env);

    // No COMP directory at all: nothing was proven.
    let mut plain = image();
    plain[0x1000..0x1004].copy_from_slice(b"ZZZZ");
    plain[KEPT..].fill(0xff);
    let env = envelope(&plain, &SPLICES);
    let decoded = decode_envelope(&env).unwrap();
    assert_eq!(decoded.image, plain);
    assert_eq!(decoded.unrecovered_tail(), Some(tail));
}

#[test]
fn find_splices_accepts_a_boundary_exactly_one_window_in() {
    // payload offset 0xf000 puts the first boundary at image offset 0x1000,
    // where the clean-before window starts at image offset 0.
    let key = make_key(0x123456, 0x1000);
    let plain = low_entropy(0x3000);
    let cipher = transform(&plain, &key, true).unwrap();
    let mut spliced = cipher[..0x1000].to_vec();
    spliced.extend((0..16u8).map(|b| b.wrapping_mul(37) ^ 0x5c));
    spliced.extend_from_slice(&cipher[0x1000..]);
    let found = find_splices(&spliced, 0xf000, &key, false);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].image_offset, 0x1000);
}

// Env-gated OEM fixture: e.g. PIONEER_SPLICED_NORMAL_FIXTURE=S8510191.103.enc
#[test]
fn spliced_normal_fixture_when_configured() {
    let Ok(path) = std::env::var("PIONEER_SPLICED_NORMAL_FIXTURE") else {
        return;
    };
    let data = std::fs::read(path).unwrap();
    let decoded = decode_envelope(&data).unwrap();
    assert_eq!(decoded.spliced_blocks().len(), 3);
    assert_eq!(decoded.repack(&decoded.image).unwrap(), data);
    if decoded.unrecovered_tail().is_none() {
        assert!(comp_streams(&decoded.image).is_some());
    }
}
