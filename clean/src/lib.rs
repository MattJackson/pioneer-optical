//! Pioneer optical-drive firmware: decode an envelope, compute corrections,
//! re-encode. **Pure byte transforms** — no hardware I/O (the SCSI transport
//! lives in the flashing app). This crate is the clean reimplementation: the
//! public surface is exactly what the sole consumer (freemkv-flash) uses, and
//! every transform is verified byte-for-byte against the frozen golden oracle
//! (`../oracle/golden-*.json`) over the real firmware corpus.
//!
//! Clean module layout (vs the legacy crate's 20 public modules / 207 files):
//!
//! | module      | job (one thing)                                              |
//! |-------------|--------------------------------------------------------------|
//! | [`envelope`]| the codec: decode / re-encode / sign a firmware envelope      |
//! | [`correct`] | compute phase + startup corrections (output bytes)           |
//! | [`classify`]| pair verdict (allowed/conditional/refused + required words) — |
//! |             | **no materialization** (the fast crossflash-scan path)       |
//! | [`prepare`] | materialize a corrected image to flash (the heavy path)       |
//! | [`cdb`]     | construct drive command bytes (no transport)                 |
//!
//! The legacy `analysis` / `filters` / `image` / `startup` modules — firmware
//! machine-code analysis used to *locate* correction sites — are ported in as
//! **private** internals under [`correct`], not public API.

// Ported incrementally, each gated on the golden oracle. Declarations are added
// here as modules land; the crate stays compiling at every step.

pub mod envelope;
// pub mod correct;   // TODO(port): phase + startup corrections
// pub mod classify;  // TODO(port): verdict-only pair classification (fast path)
// pub mod prepare;   // TODO(port): materializing transform for the flasher
// pub mod cdb;       // TODO(port): drive command-byte construction
