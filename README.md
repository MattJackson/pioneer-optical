# pioneer-optical

[![CI](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pioneer-optical.svg)](https://crates.io/crates/pioneer-optical)
[![docs.rs](https://img.shields.io/docsrs/pioneer-optical)](https://docs.rs/pioneer-optical)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![MSRV 1.75](https://img.shields.io/badge/MSRV-1.75-blue.svg)](#minimum-supported-rust-version)

The vendor protocol of **Pioneer optical drives** (BD/DVD): command encoding,
response decoding, command sequences over any SCSI transport, and firmware
image analysis.

```toml
[dependencies]
pioneer-optical = { version = "0.8", features = ["drive"] }
```

| Module | Feature | Contents |
|---|---|---|
| `cdb` | — | Vendor CDB constructors and field constants |
| `Identity` | — | Decoded INQUIRY + vendor identity; `class()` |
| `dvr` | — | DVR update-handshake challenge solver |
| `sense` | — | `05/24/00` refusal classification |
| `drive` | `drive` | `Transport` trait; `identify`, `read_memory`, `enter_update` → `Session` |
| `image` | `image` | `family`, `is_uhd`, `required_abi` / `provided_abi` |

The default build and the `drive` feature are `no_std` and allocation-free.
`image` uses `alloc` and [`miniz_oxide`](https://crates.io/crates/miniz_oxide).

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
