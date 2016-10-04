SipHash implementation for Rust
===============================

SipHash was recently removed from rust-core.

This crate brings `SipHasher`, `SipHasher13` and `SipHash24` back.
It is based on the original implementation from rust-core and exposes the
same API.

In addition, it can return 128-bit tags.

The `sip` module implements the standard 64-bit mode, whereas the `sip128`
module implements the experimental 128-bit mode.
