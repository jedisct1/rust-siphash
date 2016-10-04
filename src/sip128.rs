// Copyright 2012-2015 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An implementation of SipHash.

use std::hash;
use std::marker::PhantomData;
use std::ptr;

/// A 128-bit (2x64) hash output
#[derive(Debug, Clone, Default)]
pub struct Hash128 {
    pub h1: u64,
    pub h2: u64,
}

/// An implementation of SipHash128 1-3.
#[derive(Debug, Clone, Default)]
pub struct SipHasher13 {
    hasher: Hasher<Sip13Rounds>,
}

/// An implementation of SipHash128 2-4.
#[derive(Debug, Clone, Default)]
pub struct SipHasher24 {
    hasher: Hasher<Sip24Rounds>,
}

/// An implementation of SipHash128 2-4.
///
/// SipHash is a general-purpose hashing function: it runs at a good
/// speed (competitive with Spooky and City) and permits strong _keyed_
/// hashing. This lets you key your hashtables from a strong RNG, such as
/// [`rand::os::OsRng`](https://doc.rust-lang.org/rand/rand/os/struct.OsRng.html).
///
/// Although the SipHash algorithm is considered to be generally strong,
/// it is not intended for cryptographic purposes. As such, all
/// cryptographic uses of this implementation are _strongly discouraged_.
#[derive(Debug, Clone, Default)]
pub struct SipHasher(SipHasher24);

#[derive(Debug)]
struct Hasher<S: Sip> {
    k0: u64,
    k1: u64,
    length: usize, // how many bytes we've processed
    state: State, // hash State
    tail: u64, // unprocessed bytes le
    ntail: usize, // how many bytes in tail are valid
    _marker: PhantomData<S>,
}

#[derive(Debug, Clone, Copy)]
struct State {
    // v0, v2 and v1, v3 show up in pairs in the algorithm,
    // and simd implementations of SipHash will use vectors
    // of v02 and v13. By placing them in this order in the struct,
    // the compiler can pick up on just a few simd optimizations by itself.
    v0: u64,
    v2: u64,
    v1: u64,
    v3: u64,
}

// sadly, these macro definitions can't appear later,
// because they're needed in the following defs;
// this design could be improved.

macro_rules! u8to64_le {
    ($buf:expr, $i:expr) =>
    ($buf[0+$i] as u64 |
     ($buf[1+$i] as u64) << 8 |
     ($buf[2+$i] as u64) << 16 |
     ($buf[3+$i] as u64) << 24 |
     ($buf[4+$i] as u64) << 32 |
     ($buf[5+$i] as u64) << 40 |
     ($buf[6+$i] as u64) << 48 |
     ($buf[7+$i] as u64) << 56);
    ($buf:expr, $i:expr, $len:expr) =>
    ({
        let mut t = 0;
        let mut out = 0;
        while t < $len {
            out |= ($buf[t+$i] as u64) << t*8;
            t += 1;
        }
        out
    });
}

/// Load a full u64 word from a byte stream, in LE order. Use
/// `copy_nonoverlapping` to let the compiler generate the most efficient way
/// to load u64 from a possibly unaligned address.
///
/// Unsafe because: unchecked indexing at i..i+8
#[inline]
unsafe fn load_u64_le(buf: &[u8], i: usize) -> u64 {
    debug_assert!(i + 8 <= buf.len());
    let mut data = 0u64;
    ptr::copy_nonoverlapping(buf.get_unchecked(i), &mut data as *mut _ as *mut u8, 8);
    data.to_le()
}

macro_rules! rotl {
    ($x:expr, $b:expr) =>
    (($x << $b) | ($x >> (64_i32.wrapping_sub($b))))
}

macro_rules! compress {
    ($state:expr) => ({
        compress!($state.v0, $state.v1, $state.v2, $state.v3)
    });
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) =>
    ({
        $v0 = $v0.wrapping_add($v1); $v1 = rotl!($v1, 13); $v1 ^= $v0;
        $v0 = rotl!($v0, 32);
        $v2 = $v2.wrapping_add($v3); $v3 = rotl!($v3, 16); $v3 ^= $v2;
        $v0 = $v0.wrapping_add($v3); $v3 = rotl!($v3, 21); $v3 ^= $v0;
        $v2 = $v2.wrapping_add($v1); $v1 = rotl!($v1, 17); $v1 ^= $v2;
        $v2 = rotl!($v2, 32);
    });
}

pub trait Hasher128 {
    /// Return a 128-bit hash
    fn finish128(&self) -> Hash128;
}

impl SipHasher {
    /// Creates a new `SipHasher` with the two initial keys set to 0.
    #[inline]
    pub fn new() -> SipHasher {
        SipHasher::new_with_keys(0, 0)
    }

    /// Creates a `SipHasher` that is keyed off the provided keys.
    #[inline]
    pub fn new_with_keys(key0: u64, key1: u64) -> SipHasher {
        SipHasher(SipHasher24::new_with_keys(key0, key1))
    }
}

impl Hasher128 for SipHasher {
    /// Return a 128-bit hash
    #[inline]
    fn finish128(&self) -> Hash128 {
        self.0.finish128()
    }
}

impl SipHasher13 {
    /// Creates a new `SipHasher13` with the two initial keys set to 0.
    #[inline]
    pub fn new() -> SipHasher13 {
        SipHasher13::new_with_keys(0, 0)
    }

    /// Creates a `SipHasher13` that is keyed off the provided keys.
    #[inline]
    pub fn new_with_keys(key0: u64, key1: u64) -> SipHasher13 {
        SipHasher13 { hasher: Hasher::new_with_keys(key0, key1) }
    }
}

impl Hasher128 for SipHasher13 {
    /// Return a 128-bit hash
    #[inline]
    fn finish128(&self) -> Hash128 {
        self.hasher.finish128()
    }
}

impl SipHasher24 {
    /// Creates a new `SipHasher24` with the two initial keys set to 0.
    #[inline]
    pub fn new() -> SipHasher24 {
        SipHasher24::new_with_keys(0, 0)
    }

    /// Creates a `SipHasher24` that is keyed off the provided keys.
    #[inline]
    pub fn new_with_keys(key0: u64, key1: u64) -> SipHasher24 {
        SipHasher24 { hasher: Hasher::new_with_keys(key0, key1) }
    }
}

impl Hasher128 for SipHasher24 {
    /// Return a 128-bit hash
    #[inline]
    fn finish128(&self) -> Hash128 {
        self.hasher.finish128()
    }
}

impl<S: Sip> Hasher<S> {
    #[inline]
    fn new_with_keys(key0: u64, key1: u64) -> Hasher<S> {
        let mut state = Hasher {
            k0: key0,
            k1: key1,
            length: 0,
            state: State {
                v0: 0,
                v1: 0xee,
                v2: 0,
                v3: 0,
            },
            tail: 0,
            ntail: 0,
            _marker: PhantomData,
        };
        state.reset();
        state
    }

    #[inline]
    fn reset(&mut self) {
        self.length = 0;
        self.state.v0 = self.k0 ^ 0x736f6d6570736575;
        self.state.v1 = self.k1 ^ 0x646f72616e646f83;
        self.state.v2 = self.k0 ^ 0x6c7967656e657261;
        self.state.v3 = self.k1 ^ 0x7465646279746573;
        self.ntail = 0;
    }
}


impl<S: Sip> Hasher<S> {
    #[inline]
    pub fn finish128(&self) -> Hash128 {
        let mut state = self.state;

        let b: u64 = ((self.length as u64 & 0xff) << 56) | self.tail;

        state.v3 ^= b;
        S::c_rounds(&mut state);
        state.v0 ^= b;

        state.v2 ^= 0xee;
        S::d_rounds(&mut state);
        let h1 = state.v0 ^ state.v1 ^ state.v2 ^ state.v3;

        state.v1 ^= 0xdd;
        S::d_rounds(&mut state);
        let h2 = state.v0 ^ state.v1 ^ state.v2 ^ state.v3;

        Hash128 { h1: h1, h2: h2 }
    }
}

impl hash::Hasher for SipHasher {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.0.write(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.0.finish()
    }
}

impl hash::Hasher for SipHasher13 {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.hasher.write(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hasher.finish()
    }
}

impl hash::Hasher for SipHasher24 {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        self.hasher.write(msg)
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.hasher.finish()
    }
}

impl<S: Sip> hash::Hasher for Hasher<S> {
    #[inline]
    fn write(&mut self, msg: &[u8]) {
        let length = msg.len();
        self.length += length;

        let mut needed = 0;

        if self.ntail != 0 {
            needed = 8 - self.ntail;
            if length < needed {
                self.tail |= u8to64_le!(msg, 0, length) << 8 * self.ntail;
                self.ntail += length;
                return;
            }

            let m = self.tail | u8to64_le!(msg, 0, needed) << 8 * self.ntail;

            self.state.v3 ^= m;
            S::c_rounds(&mut self.state);
            self.state.v0 ^= m;

            self.ntail = 0;
        }

        // Buffered tail is now flushed, process new input.
        let len = length - needed;
        let left = len & 0x7;

        let mut i = needed;
        while i < len - left {
            let mi = unsafe { load_u64_le(msg, i) };

            self.state.v3 ^= mi;
            S::c_rounds(&mut self.state);
            self.state.v0 ^= mi;

            i += 8;
        }

        self.tail = u8to64_le!(msg, i, left);
        self.ntail = left;
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.finish128().h2
    }
}

impl<S: Sip> Clone for Hasher<S> {
    #[inline]
    fn clone(&self) -> Hasher<S> {
        Hasher {
            k0: self.k0,
            k1: self.k1,
            length: self.length,
            state: self.state,
            tail: self.tail,
            ntail: self.ntail,
            _marker: self._marker,
        }
    }
}

impl<S: Sip> Default for Hasher<S> {
    /// Creates a `Hasher<S>` with the two initial keys set to 0.
    #[inline]
    fn default() -> Hasher<S> {
        Hasher::new_with_keys(0, 0)
    }
}

#[doc(hidden)]
trait Sip {
    fn c_rounds(&mut State);
    fn d_rounds(&mut State);
}

#[derive(Debug, Clone, Default)]
struct Sip13Rounds;

impl Sip for Sip13Rounds {
    #[inline]
    fn c_rounds(state: &mut State) {
        compress!(state);
    }

    #[inline]
    fn d_rounds(state: &mut State) {
        compress!(state);
        compress!(state);
        compress!(state);
    }
}

#[derive(Debug, Clone, Default)]
struct Sip24Rounds;

impl Sip for Sip24Rounds {
    #[inline]
    fn c_rounds(state: &mut State) {
        compress!(state);
        compress!(state);
    }

    #[inline]
    fn d_rounds(state: &mut State) {
        compress!(state);
        compress!(state);
        compress!(state);
        compress!(state);
    }
}

impl Hash128 {
    /// Convert into a 16-bytes vector
    pub fn into_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; 16];
        let h1 = self.h1.to_le();
        let h2 = self.h2.to_le();
        unsafe {
            ptr::copy_nonoverlapping(&h1 as *const _ as *const u8, bytes.get_unchecked_mut(0), 8);
            ptr::copy_nonoverlapping(&h2 as *const _ as *const u8, bytes.get_unchecked_mut(8), 8);
        }
        bytes
    }
}
