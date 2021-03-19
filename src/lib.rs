#![cfg_attr(not(test), no_std)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_lossless)]

pub mod sip;
pub mod sip128;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod tests128;

#[cfg(feature = "serde")]
pub mod reexports {
    pub use serde;
}
