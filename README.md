# pioneer-optical

[![CI](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MattJackson/pioneer-optical/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/pioneer-optical.svg)](https://crates.io/crates/pioneer-optical)
[![docs.rs](https://img.shields.io/docsrs/pioneer-optical)](https://docs.rs/pioneer-optical)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![MSRV 1.75](https://img.shields.io/badge/MSRV-1.75-blue.svg)](#minimum-supported-rust-version)

The vendor SCSI command catalogue for **Pioneer optical drives** (BD/DVD), as
named, documented CDB constructors.

This is a **pure data** crate: every function returns the raw 10-byte CDB and
performs no I/O. Any transport — a flasher, an unlocker, a diagnostic — can
depend on it and issue the commands itself. It is `#![no_std]`, allocation-free,
unsafe-free, and has **zero dependencies**. Its only job is to be the *single
source of truth* for the Pioneer vendor command set, so no project has to carry
magic CDB byte-arrays scattered through its code.

```toml
[dependencies]
pioneer-optical = "0.5"
```

```rust
use pioneer_optical as po;

// Read-unlock, then read protected memory.
dev.command_out(&po::knock(), &[])?;            // 3B 02 41 A5 AA AA
let block = dev.command_in(&po::read_memory(0x010000, 0xA4), 0xA4)?; // 3C 02 B0 ...

// Identity (no unlock needed).
let id = dev.command_in(&po::vendor_identity(), 48)?;               // 3C 02 F1 ...
```

## The two independent privilege unlocks

A Pioneer drive gates two capabilities behind two **distinct, independent** vendor
unlocks:

| | Command | Opens | Scope |
|---|---|---|---|
| **read unlock** (the "knock") | [`knock`] `3B 02 41 A5 AA AA` | `read_memory` (`3C 02 B0`) of protected memory above `0x8000`, to ceiling `0x880300` | reads only — proven firmware-wide read-only |
| **write unlock** ("kernel mode") | [`kernel_mode_arm`] → [`kernel_mode_challenge`] → [`kernel_mode_response`] (`F3`/`F2`) | the OEM write-accept path (Kernel `07/FE` and Normal `07/F0`) | writes — challenge/response |

Neither unlock enables the other; they set disjoint drive state. The knock is the
only setter of the read-enable flag, and the vendor identity read (`3C 02 F1`)
unlocks nothing.

## Command catalogue

All CDBs are 10 bytes; 24-bit offsets/lengths are big-endian.

| Purpose | Constructor | CDB |
|---|---|---|
| Vendor identity (48 B) | `vendor_identity()` | `3C 02 F1 00 00 00 00 00 30 00` |
| Gated memory read | `read_memory(off, len)` | `3C 02 B0 <off3> <len3> 00` |
| Read-unlock knock | `knock()` | `3B 02 41 A5 AA AA 00 00 00 00` |
| Enter update mode | `enter_update()` | `3B 04 FF 00 00 00 00 01 00 00` |
| Transfer Kernel chunk | `transfer_kernel(off, len)` | `3B 07 FE <off3> <len3> 00` |
| Transfer Normal chunk | `transfer_normal(off, len)` | `3B 07 F0 <off3> <len3> 00` |
| Finish / commit | `finish()` | `3B 05 FF 00 00 00 00 01 00 00` |
| Kernel-mode arm | `kernel_mode_arm()` | `3B 01 F3 00 00 00 00 00 00 00` |
| Kernel-mode challenge | `kernel_mode_challenge()` | `3C 01 F2 00 00 00 00 04 00 00` |
| Kernel-mode response | `kernel_mode_response()` | `3B 01 F2 00 00 00 00 01 00 00` |
| INQUIRY / TUR / GES | `inquiry()` / `test_unit_ready()` / `get_event_status()` | — |

## Safety

Issuing the OEM update sequence (`enter_update` → `transfer_*` → `finish`) or the
kernel-mode write unlock **writes to drive firmware and can brick the drive**.
This crate only produces the command bytes; the caller is responsible for backups,
gating, and confirming the drive and image are correct. The memory-read and
identity commands are read-only.

## Scope and provenance

The catalogue is for the Renesas-based "SAT" generation of Pioneer BD writers
(reference platform BDR-UD04, `SAT 8A10`). Command bytes are recovered by
reverse engineering and corroborated on real hardware; the read-unlock knock and
its address ceiling are confirmed on a live BDR-UD04. This crate does not hold or
ship any OEM key.

## Minimum supported Rust version

1.75.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
