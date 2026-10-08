//! Tests for banner and embedded-identity parsing.
//!
//! The fixtures are distilled from the real firmware corpus (~1100 Pioneer and
//! rebadge images): every INQUIRY identity string and banner shape below was
//! observed in a genuine `.fw.bin` / envelope. They exercise the spacing,
//! media-class and model-only variants the parser must handle flawlessly.

use super::*;

// ---- Banner parsing --------------------------------------------------------

/// Assemble a plaintext banner from field lines, each `\r\n`-terminated, the
/// way genuine Pioneer `.fw.bin` images are laid out.
fn banner_bytes(lines: &[&str]) -> Vec<u8> {
    let mut v = Vec::new();
    for line in lines {
        v.extend_from_slice(line.as_bytes());
        v.extend_from_slice(b"\r\n");
    }
    v.extend_from_slice(&[0u8; 32]); // trailing NUL padding, as on real images
    v
}

const MAGIC_LINE: &str = "********  Copyright(c) 2000 Pioneer Corporation  ********     ";

#[test]
fn banner_real_fixtures_parse_exactly() {
    // (lines, expected model/revision/hardware/destination/file_type).
    // Each row is a real banner observed in the corpus.
    struct Case {
        lines: &'static [&'static str],
        model: &'static str,
        revision: &'static str,
        hardware: &'static str,
        destination: &'static str,
        file_type: &'static str,
    }
    let cases = [
        // BDR-212U FW 1.05 (the drive from the field report) — 3-space ID, ID58.
        Case {
            lines: &[
                MAGIC_LINE,
                "ID : PIONEER BD-RW   BDR-212U",
                "Revision Level : 1.05 ",
                "Hardware Version : SAT 8F01",
                "Kernel Version : ID58    ",
                "Destination : ID58    ",
                "File Type : Normal  ",
                "Kernel Version2 : 0000",
            ],
            model: "BDR-212U",
            revision: "1.05",
            hardware: "SAT 8F01",
            destination: "ID58",
            file_type: "Normal",
        },
        // BDR-S09 1.55 — model has a trailing space before the terminator.
        Case {
            lines: &[
                MAGIC_LINE,
                "ID : PIONEER BD-RW   BDR-S09 ",
                "Revision Level : 1.55 ",
                "Hardware Version : SAT 8600",
                "Kernel Version : ID43    ",
                "Destination : ID43    ",
                "File Type : Normal  ",
                "Kernel Version2 : 0000",
            ],
            model: "BDR-S09",
            revision: "1.55",
            hardware: "SAT 8600",
            destination: "ID43",
            file_type: "Normal",
        },
        // BDR-XS06 1.11 — GENERAL destination (not a kernel tag).
        Case {
            lines: &[
                MAGIC_LINE,
                "ID : PIONEER BD-RW   BDR-XS06",
                "Revision Level : 1.11 ",
                "Hardware Version : SAT 8722",
                "Kernel Version : GENERAL ",
                "Destination : GENERAL ",
                "File Type : Normal  ",
                "Kernel Version2 : 0000",
            ],
            model: "BDR-XS06",
            revision: "1.11",
            hardware: "SAT 8722",
            destination: "GENERAL",
            file_type: "Normal",
        },
        // A Kernel component (File Type : Kernel), same layout.
        Case {
            lines: &[
                MAGIC_LINE,
                "ID : PIONEER BD-RW   BDR-212U",
                "Revision Level : 1.05 ",
                "Hardware Version : SAT 8F01",
                "Kernel Version : ID58    ",
                "Destination : ID58    ",
                "File Type : Kernel  ",
                "Kernel Version2 : 0000",
            ],
            model: "BDR-212U",
            revision: "1.05",
            hardware: "SAT 8F01",
            destination: "ID58",
            file_type: "Kernel",
        },
    ];
    for c in cases {
        let b = parse_banner(&banner_bytes(c.lines))
            .unwrap_or_else(|| panic!("banner failed to parse: {:?}", c.lines[1]));
        assert_eq!(b.model, c.model, "model for {:?}", c.lines[1]);
        assert_eq!(b.revision, c.revision, "revision for {:?}", c.lines[1]);
        assert_eq!(b.hardware, c.hardware, "hardware for {:?}", c.lines[1]);
        assert_eq!(
            b.destination, c.destination,
            "destination for {:?}",
            c.lines[1]
        );
        assert_eq!(b.file_type, c.file_type, "file_type for {:?}", c.lines[1]);
    }
}

#[test]
fn banner_peels_internal_trailing_dot_on_revision() {
    // Some older banners pad a field as "1.11 ." — the lone trailing dot is peeled.
    let b = parse_banner(&banner_bytes(&[
        MAGIC_LINE,
        "ID : PIONEER DVD-RW  DVR-112",
        "Revision Level : 1.11 .",
        "Hardware Version : 0013",
        "Destination : GENERAL ",
        "File Type : Normal  ",
    ]))
    .expect("parse");
    assert_eq!(b.model, "DVR-112");
    assert_eq!(b.revision, "1.11");
}

#[test]
fn banner_requires_magic_and_model() {
    // No magic → None.
    assert!(parse_banner(b"not a pioneer image").is_none());
    assert!(parse_banner(&[]).is_none());
    // Magic present but no ID line → None.
    assert!(parse_banner(&banner_bytes(&[MAGIC_LINE, "Revision Level : 1.00 "])).is_none());
}

// ---- Embedded identity recovery --------------------------------------------

/// Place `id` inside an image at a realistic offset, bounded by a NUL so the
/// token-boundary check treats it as a whole identity.
fn image_with(id: &str) -> Vec<u8> {
    let mut v = vec![0xABu8; 0x40];
    v.extend_from_slice(id.as_bytes());
    v.push(0x00);
    v.extend_from_slice(&[0xCD; 0x20]);
    v
}

#[test]
fn embedded_id_real_fixtures_round_trip() {
    // (vendor field, product field, expected embedded identity) — all observed
    // in the corpus. Covers 3/2/1-space media→model, DVD/BD-ROM media,
    // internal-space media, non-PIONEER rebadges, and model-only products.
    let cases = [
        ("PIONEER", "BD-RW   BDR-212U", "PIONEER BD-RW   BDR-212U"), // 3 spaces
        ("PIONEER", "BD-RW  BDR-XD07U", "PIONEER BD-RW  BDR-XD07U"), // 2 spaces
        ("PIONEER", "BD-RW BDR-XS07JL", "PIONEER BD-RW BDR-XS07JL"), // 1 space
        ("PIONEER", "BD-RW BDR-209MIO", "PIONEER BD-RW BDR-209MIO"), // 1 space, long model
        ("PIONEER", "DVD-RW  DVR-212", "PIONEER DVD-RW  DVR-212"),   // DVD media
        ("PIONEER", "BD-ROM  BDC-202", "PIONEER BD-ROM  BDC-202"),   // BD-ROM media
        ("Optiarc", "BD ROM BC-5100S", "Optiarc BD ROM BC-5100S"),   // internal-space media
        ("ASUS", "BW-16D1X-U", "ASUS BW-16D1X-U"),                   // model-only rebadge
        ("PIONEER", "BDR-PR1EPDVPP100", "PIONEER BDR-PR1EPDVPP100"), // model-only, len==24
        ("PIONEER", "BDR-PR1MD2MCM", "PIONEER BDR-PR1MD2MCM"),       // model-only (field report)
    ];
    for (vendor, product, expected) in cases {
        let img = image_with(expected);
        let got = embedded_envelope_id(vendor, product, &[&img])
            .unwrap_or_else(|e| panic!("recovery failed for {product:?}: {e}"));
        assert_eq!(got, expected, "for product {product:?}");
    }
}

#[test]
fn embedded_id_searches_kernel_then_normal() {
    let id = "PIONEER BD-RW   BDR-212U";
    let empty: &[u8] = &[];
    let normal = image_with(id);
    // First image empty → falls through to the second.
    let got = embedded_envelope_id("PIONEER", "BD-RW   BDR-212U", &[empty, &normal]).unwrap();
    assert_eq!(got, id);
}

#[test]
fn embedded_id_via_identity_method() {
    let id = "PIONEER BD-RW   BDR-212U";
    let mut inquiry = [b' '; crate::INQUIRY_LEN];
    inquiry[8..15].copy_from_slice(b"PIONEER");
    inquiry[16..32].copy_from_slice(b"BD-RW   BDR-212U");
    let ident = Identity::parse(&inquiry, &[0u8; 44]).expect("identity");
    let img = image_with(id);
    assert_eq!(ident.embedded_envelope_id(&[&img]).unwrap(), id);
}

#[test]
fn embedded_id_rejects_model_that_is_a_prefix() {
    // Image holds the longer model; searching the shorter prefix must not match.
    let img = image_with("PIONEER BD-RW   BDR-212U");
    assert_eq!(
        embedded_envelope_id("PIONEER", "BD-RW   BDR-212", &[&img]),
        Err(IdentError::NotFound)
    );
    // The exact model, bounded, matches.
    let exact = image_with("PIONEER BD-RW   BDR-212");
    assert_eq!(
        embedded_envelope_id("PIONEER", "BD-RW   BDR-212", &[&exact]).unwrap(),
        "PIONEER BD-RW   BDR-212"
    );
}

#[test]
fn embedded_id_accepts_identity_abutting_its_revision() {
    // Some layouts place the revision directly after the identity with no NUL:
    // "...BDR-212U1.05 ". The ` X.XX ` tail is accepted as a boundary.
    let mut img = vec![0u8; 0x20];
    img.extend_from_slice(b"PIONEER BD-RW   BDR-212U1.05 ");
    img.extend_from_slice(&[0u8; 0x10]);
    assert_eq!(
        embedded_envelope_id("PIONEER", "BD-RW   BDR-212U", &[&img]).unwrap(),
        "PIONEER BD-RW   BDR-212U"
    );
}

#[test]
fn embedded_id_ambiguous_when_two_spacings_present() {
    // The same model embedded at two different vendor→model gaps is ambiguous.
    let mut img = image_with("PIONEER BD-RW BDR-X12");
    img.extend_from_slice(&image_with("PIONEER BD-RW  BDR-X12"));
    assert_eq!(
        embedded_envelope_id("PIONEER", "BD-RW BDR-X12", &[&img]),
        Err(IdentError::Ambiguous)
    );
}

#[test]
fn embedded_id_rejects_incomplete_inputs() {
    let img = image_with("PIONEER BD-RW   BDR-212U");
    // Empty vendor.
    assert_eq!(
        embedded_envelope_id("", "BD-RW   BDR-212U", &[&img]),
        Err(IdentError::IncompleteIdentity)
    );
    // No model token in product.
    assert_eq!(
        embedded_envelope_id("PIONEER", "   ", &[&img]),
        Err(IdentError::NoModel)
    );
    // Nothing matches in the image.
    assert_eq!(
        embedded_envelope_id("PIONEER", "BD-RW   BDR-999Z", &[&img]),
        Err(IdentError::NotFound)
    );
}
