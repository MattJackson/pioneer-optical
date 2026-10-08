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

The default build and the `drive` feature are `no_std` and allocation-free.
`image` uses `alloc` and [`miniz_oxide`](https://crates.io/crates/miniz_oxide).
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
