//! Materialize a corrected update against the installed receiver.
//!
//! [`Receiver`] is built from the installed firmware (a pre-flash backup).
//! [`Receiver::prepare`] / [`Receiver::prepare_normal`] run every admission
//! gate and return an opaque plan whose stages yield the exact byte streams
//! to write and the settings transaction to run before the first transfer.

pub use crate::receiver::{
    BridgeKind, PreparationError, PreparedNormal, PreparedStage, PreparedUpdate, Receiver,
};

/// The Normal transfer the receiving Kernel accepts: keep, sign or re-encode.
pub use crate::receiver::normal_transfer::{
    for_receiver as normal_for_receiver, is_unsigned, sign_for_receiver, NormalTransferError,
};

/// The settings transaction a prepared stage runs before its first transfer.
pub use crate::settings::update::{
    Effect as SettingEffect, Key as SettingKey, Plan as SettingsPlan, Setting as SettingEntry,
};

/// The startup word a prepared update selects.
pub use crate::startup::Setting as StartupSetting;
