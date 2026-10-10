# pioneer-optical

[![CI](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pioneer-optical.svg)](https://crates.io/crates/pioneer-optical)
[![docs.rs](https://img.shields.io/docsrs/pioneer-optical)](https://docs.rs/pioneer-optical)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![MSRV 1.75](https://img.shields.io/badge/MSRV-1.75-blue.svg)](#minimum-supported-rust-version)

The vendor protocol of **Pioneer optical drives** (BD/DVD): command encoding,
response decoding, command sequences over any SCSI transport, firmware image
analysis, and the firmware envelope codec (decode, repack, build, sign).

```toml
[dependencies]
pioneer-optical = { version = "0.11", features = ["drive"] }
```

| Module | Feature | Contents |
|---|---|---|
| `cdb` | — | Vendor CDB constructors and field constants |
| `Identity` | — | Decoded INQUIRY + vendor identity; `class()` |
| `dvr` | — | DVR update-handshake challenge solver |
| `sense` | — | `05/24/00` refusal classification |
| `drive` | `drive` | `Transport` trait; `identify`, `read_memory`, `enter_update` → `Session` |
| `image` | `image` | `family`, `is_uhd`, `required_abi` / `provided_abi` |
| `envelope` | `envelope` | `Envelope::load`, `DecodeError`, `header_info`, `DecodedEnvelope::repack`; `signature`, `builder`; `Error`, `Layout`; `ComponentKind` at the root |

The optional `firmware-info` feature exposes `firmware::{layout, callbacks, abi}`
for structural H8 memory maps, dispatch callback discovery, and bounded argument
tracing. These APIs report evidence from a decoded firmware image; they do not
reserve live RAM, construct payloads, or install hooks. Unsupported or ambiguous
patterns are errors. This feature requires `std` and the shared COMP decoder.

`drive::diagnostic_memory` transfers caller-provided bytes through a diagnostic
selector in bounded chunks with exact transfer-count checks. The caller owns
address selection, diagnostic enablement, payload interpretation, and recovery.

The default build and the `drive` feature are `no_std` and allocation-free.
`image` uses `std`, `alloc`, [`h8-asm`](https://crates.io/crates/h8-asm), and
[`miniz_oxide`](https://crates.io/crates/miniz_oxide). The shared H8 decoder
currently requires `std`; the default and `drive` builds remain `no_std`.
`firmware-info` adds read-only inspection and serialization without enabling
envelope encoding, signing, random-number generation, or big integers.
`envelope` implies `image` and `std`.

`Envelope::load` detects a codec from file contents. Unsupported formats,
ambiguous framing, and malformed payloads produce distinct errors. Successful
loading establishes envelope framing only; it does not establish compatibility
with a drive or permission to flash. Sparse checksum wrappers expose their
stored payload without claiming an internal instruction set or receiver protocol.

`Envelope::load_with_kernel` also recognizes legacy boot-key formats when the
supplied Kernel contains the supported decoder and checksum routines. This
includes M32C and M7900 layouts. Keys come from that Kernel, and decoded checksums
are verified before returning an envelope. A decoded legacy envelope can be
repacked losslessly even when no receiver transfer representation is supported.

## Live device information and settings

The `drive` feature also exposes `device::Device`, an allocation-free facade over
an existing `Transport`. `info()` reads identity, mechanics and MMC descriptors;
`settings()` reads one consistent vendor capability block; `snapshot()` retains
independent results so an unsupported query never hides successful information.

```rust,ignore
use pioneer_optical::device::{Device, QuietDrive, PureRead, DvdRegion};
use pioneer_optical::device::settings::{Persistence, QuietMode, PureReadValue,
    PureReadMode, Region, Persistent};

let mut device = Device::new(&mut transport);
let snapshot = device.snapshot(); // Reads only.
let quiet = device.get(QuietDrive)?;
let outcome = device.set(QuietDrive, QuietMode::Quiet, Persistence::Volatile)?;
let outcome = device.set(PureRead,
    PureReadValue { mode: PureReadMode::Perfect, real_time: false },
    Persistence::Saved)?;
let outcome = device.set(DvdRegion, Region::new(2).unwrap(), Persistent)?;
```

`Readable` and `Writable` keep each setting's state, legal input, and persistence
policy typed. Unknown wire values remain `Observed::Unknown`; they are never
silently converted to a default mode. Support comes from the connected firmware's
F4 flags, not a model/revision list. Earlier layouts without a write-capability
flag report unknown. Unrecognized response layouts are rejected. This is generic
protocol support, **not a claim that every Pioneer firmware has been validated**.

The transport-independent `settings::Codec` owns query bytes, response decoding,
write encodings, choices, and persistence metadata. `VendorF4` handles recognized
F4 variants, including older boolean feature-prefix responses; `FF FF` is not a
universal signature. `Device::with_settings_codec` selects another proven
implementation without changing the UI or the typed get/set API. An envelope
codec is not evidence of a drive-settings protocol. Unknown layouts never select
a speculative write implementation.

`Settings::entries()` supplies stable setting IDs, typed choices, active/saved
values, version, write support, and volatile/saved policies. Unsupported parent
features omit every child, including PureRead version and real-time processing.
A custom codec defaults to read-only; it must explicitly provide controls and
write encodings. Defined choices are not a per-choice hardware support bitset.
`F4Response` retains the raw block for offline decoding and unknown extensions.

`set` re-reads support, validates the input, writes once, and reads back. Its
`WriteOutcome` distinguishes verified live state, mismatch, and an accepted write
whose verification failed. EEPROM retention across a power cycle is not verified.
A transport failure during a write can also leave its outcome uncertain; callers
must not blindly retry. Quiet mode selection requests optimal read/write speeds.
`PersistentQuiet` is a quiet mode; `Persistence::Saved` is the separate EEPROM
choice. Region uses an inherently persistent policy and honors remaining counts.

Manufacturing provenance, optical labeling support and BDXL support are not
inferred from model strings or ordinary BD profile presence. The API preserves
raw responses for additional decoders. No snapshot enters update mode, changes
region, saves settings, or performs speculative vendor writes.

## Locating Normal for backup

With `envelope` enabled, a decoded H8 Kernel can establish its companion Normal's
capture geometry without probing a contiguous device memory map:

```rust,ignore
let layout = kernel_envelope.normal_layout()?;
// For raw captured bytes instead:
// let layout = NormalLayout::from_kernel(&kernel_bytes, kernel_address)?;
let prefix = layout.header_region();
let header = read_exact(prefix.address(), prefix.length())?;
let region = layout.resolve(&header)?;
let normal = read_exact(region.address(), region.length())?;
layout.validate(&normal)?;
```

The caller owns transport, repeated-read verification and backup persistence.
The library recognizes aligned checksum and descriptor-check instruction sequences
and requires their addresses to agree. Fixed-extent layouts additionally require
agreement with the Kernel's decoder geometry. Unsupported or ambiguous code is an
error, never a guessed address. This API currently covers the 64 KiB H8 Kernel
capture format; envelope support for other architectures does not imply live
backup support. Capture geometry does not establish flash compatibility.

## Example

```rust,ignore
use pioneer_optical::{drive, Role};

struct Sg(/* your pass-through */);

impl drive::Transport for Sg {
    type Error = std::io::Error;
    fn exec(&mut self, cdb: &[u8], data: drive::Data<'_>) -> Result<usize, Self::Error> {
        /* issue `cdb`; fill or send `data` */
    }
    fn sense(&self) -> Option<(u8, u8, u8)> { /* last sense */ }
}

let id = drive::identify(&mut t)?;
let class = id.class().ok_or(drive::Error::UnknownClass)?;
let mut session = drive::enter_update(&mut t, class, &control)?;
session.write(Role::Kernel, 0, &kernel)?;
session.write(Role::Normal, 0, &normal)?;
session.finish()?;
```

## Command set

All vendor CDBs are 10 bytes; offsets and lengths are 24-bit big-endian.

| Command | Constructor | CDB |
|---|---|---|
| Vendor identity (48 B) | `cdb::vendor_identity()` | `3C 02 F1 00 00 00 00 00 30 00` |
| Memory read | `cdb::read_memory(off, len)` | `3C 02 B0 <off> <len> 00` |
| Enable extended read | `cdb::knock()` | `3B 02 41 A5 AA AA 00 00 00 00` |
| Enter update | `cdb::enter_update()` | `3B 04 FF 00 00 00 00 01 00 00` |
| Write Kernel / Normal chunk | `cdb::transfer(role, off, len)` | `3B 07 FE\|F0 <off> <len> 00` |
| Commit update | `cdb::finish()` | `3B 05 FF 00 00 00 00 01 00 00` |
| DVR arm | `cdb::dvr_arm()` | `3B 01 F3 00 00 00 00 00 00 00` |
| DVR challenge | `cdb::dvr_challenge()` | `3C 01 F2 00 00 00 00 04 00 00` |
| DVR response | `cdb::dvr_response()` | `3B 01 F2 00 00 00 00 01 00 00` |

## Safety

An update session writes drive firmware. A wrong image, or an interrupted
session, can leave the drive unusable. The memory-read and identity commands
are read-only.

## Minimum supported Rust version

1.75.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).

Diagnostic support is split into bounded read definitions (`diagnostic`) and
firmware-derived logging capabilities (`logging`, with the `image` feature).
`logging::discover` accepts an address-aligned CPU image, validates a supported
handler structure and returns its mask address and dispatcher group. It uses no
model/version allowlist; missing or ambiguous structures return `None`.
With `drive` enabled, `set_logging_ram` and `set_logging_persistent` preserve
unrelated mask bits and verify the live mask. The persistent setter explicitly
writes nonvolatile settings; neither setter falls back to the other. A verified
live mask does not prove persistence across a power cycle. File layout, capture
ordering and whether optional failures should abort are the host application's
responsibility.

### Error codes

Typed errors implement `pioneer_optical::CodedError`. `error.code()` returns a
stable namespaced identifier such as `pioneer.receiver.family_mismatch`.
Applications can use these identifiers as translation keys and match the error
variant for parameters. Codes contain no runtime values; English `Display`
messages are diagnostic text, not a parsing contract. Wrapper errors retain their
own stage code and typed causes. Handle unknown future codes with a generic
message and preserve the diagnostic details.

Envelope inspection also exposes `header()`, `encoding_key()`, `encoding_seed()`,
`signature_bytes()`, `signature_status()` and `reconstruction_placeholder()`.

`clone_kernel(source, &KernelIdentity { drive_name, hardware, kernel_tag,
kernel_version2 }, &KernelBuild { .. })` re-identifies an existing Kernel. Kernel
content is the decoded image minus the identity block, drive name, checksum and
the build's positional fill stream (`kernel_content_mask`); a clone keeps the
content and fills with the seed-0 stream, so `kernel_fill_seed(image) == Some(0)`
identifies it. Cloning does not establish that a drive accepts the result.
These report format facts, not manufacturer provenance. A valid mathematical
signature does not identify an OEM signer. A zero seed alone is not a placeholder;
Normal detection additionally requires an entirely zero signature slot, and Kernel
detection requires revision `0000` and date `00/00/00`. A non-matching image is
not thereby proven OEM. Raw encoding keys may legitimately have no LCG seed.


### Single-envelope analysis

The optional `analysis` feature enables `Envelope::analyze(options, observer)`.
It exposes decoded regions, expanded streams, recognized tables and metadata,
runtime addresses where established, and direct instruction-reference facts.
Unrecognized data remains available as bytes. The observer supports progress
and cooperative cancellation, and expansion is bounded by the supplied options.

This API describes one envelope. Pairing two analyses, aligning their contents,
resolving cross-image correspondence and calculating differences belong to the
consumer. The one pairwise check provided is Kernel program equality
(`kernel_equality`), whose masked fields are fixed by the Kernel format.

## Device-settings firmware audit

The generic live decoder was checked against decoded H8 Normal images for
BDR-XD08U 1.02, BDR-XD06U 1.12, and a local UD04 capture. The existing structural
opcode-registry decoder locates READ BUFFER without hardcoded model addresses.
`cargo run --all-features --example device_firmware_scan -- NORMAL.bin ...`
(or a directory containing `.enc`/`.bin` images)
prints the F4 branch and literal response stores for recognized layouts. The
scanner is an audit aid: literal stores are evidence, not complete symbolic
execution or proof of a drive's current state.

In XD08U 1.02, READ BUFFER at `0x4455d4` routes F4 to `0x445960`: response bytes
9/45 are 1, byte 29 is 0, and byte 49 is 4. XD06U 1.12's corresponding callback
is `0x445646`, with F4 at `0x4459d2`: byte 45 is 1 even though byte 43 is 0.
Requiring byte 43 as a global support gate would incorrectly suppress its Quiet
Drive controls. The UD04 capture's F4 builder at `0x445892` explicitly writes
zero to PureRead support byte 9 and unavailable sentinels to several mode fields.

The XD08U WRITE BUFFER callback at `0x44bb74` routes FA to `0x44bd0e`. It dispatches
little-endian command 0x8001 at `0x44bd60`, consumes PureRead input bytes 2–4, and
checks byte 5 at `0x44be62` before saving. Its internal master-mode retry value is
normalized when constructing the F4 response. UD04's Quiet Drive response byte 2
reads live state via `0x455568`; byte 3 reads saved key 0xA9 via `0x45556e`.
The mode setter at `0x45557e` saves that key only through its explicit save branch
at `0x455646`. These addresses document the inspected images, not runtime tables.

Additional command-format cross-checks: [OptiScan's Pioneer protocol implementation](https://github.com/dhucul/OptiScan/blob/main/PioneerVendor.cpp),
[sg3_utils MMC descriptor decoder](https://github.com/hreinecke/sg3_utils/blob/master/src/sg_get_config.c),
and the [MMC-4 draft](https://www.13thmonkey.org/documentation/SCSI/mmc4r05a.pdf).
Hardware writes have not been exercised as part of this implementation.

The 2026-10-08 census covered all 1,151 Pioneer images in the local hoard: 370
Kernel images were inventoried separately, 230 Normal response builders were
recognized, 308 images had unrecognized dispatch, 221 had absent/ambiguous F4
branches, and 22 could not be decoded. These counts are offline code coverage,
not hardware validation. `firmware::settings::inspect` exposes the same bounded
analysis with source addresses. Literal assignments do not resolve conditional
execution or dynamic fields. The per-image census is in
`tests/evidence/device-settings-hoard-2026-10-08.json`.

SAT 8221 Normal 1.41, SHA-256
`44e9069d1e6df342bced2e076a56541eedf5d99d54f9a025d942a3725bd6e71a`,
constructs F4 at `0x4457b8`. It writes boolean feature flags at offsets 0/1,
active/saved Quiet modes at 2/3, PureRead support at 9, and unavailable sentinels
at 11–14. The live decoder accepts this structurally checked prefix variant;
it still rejects zero-filled, all-FF, truncated, and unrecognized responses.
