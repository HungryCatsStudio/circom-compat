//! Safe-ish interface for reading and writing specific types to the WASM runtime's memory
use ark_serialize::CanonicalDeserialize;
use num_traits::ToPrimitive;
use wasmer::{Memory, Store};

// TODO: Decide whether we want Ark here or if it should use a generic BigInt package
use ark_bn254::FrConfig;
use ark_ff::MontConfig;
use ark_ff::{BigInteger, BigInteger256, Zero};

use num_bigint::{BigInt, BigUint};

use color_eyre::Result;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::{convert::TryFrom, ops::Deref};

/// `SafeMemory` is a wrapper around the Wasm `Memory` instance that is intended to provide a safer/simpler
/// interface for witness computation in their natural language.
///
/// Memory Layout:
/// [0-3]   : Free Position Pointer (u32):
/// [4-7]   : (Possibly unused or reserved)
/// [8..]   : Begin allocating: eg. first allocated u32 (4 bytes data + 4 bytes padding/metadata)
/// ...     : More allocated memory
#[derive(Clone, Debug)]
pub struct SafeMemory {
    /// Memory instances must be associated with a store.
    store: Arc<RwLock<Store>>,
    pub memory: Memory,

    pub prime: BigInt,

    short_max: BigInt,
    short_min: BigInt,
    r_inv: BigInt,
    /// Number of 32-bit limbs required to represent a field element
    limbs_32: usize,
}

impl Deref for SafeMemory {
    type Target = Memory;

    fn deref(&self) -> &Self::Target {
        &self.memory
    }
}

impl SafeMemory {
    /// Creates a new SafeMemory
    pub fn new(store: Arc<RwLock<Store>>, memory: Memory, limbs_32: usize, prime: BigInt) -> Self {
        // TODO: Figure out a better way to calculate these
        let short_max = BigInt::from(0x8000_0000u64);
        let short_min =
            BigInt::from_biguint(num_bigint::Sign::NoSign, BigUint::from(FrConfig::MODULUS))
                - &short_max;
        let r_inv = BigInt::from_str(
            "9915499612839321149637521777990102151350674507940716049588462388200839649614",
        )
        .unwrap();

        Self {
            store,
            memory,
            prime,

            short_max,
            short_min,
            r_inv,
            limbs_32,
        }
    }

    /// Returns the next free position in the memory
    pub fn free_pos(&self) -> u32 {
        let store = self.store.read().unwrap();
        let view = self.memory.view(&*store);
        let mut buf = [0u8; 4];
        view.read(0, &mut buf).unwrap();
        u32::from_le_bytes(buf)
    }

    /// Sets the next free position in the memory
    pub fn set_free_pos(&mut self, ptr: u32) {
        self.write_u32(0, ptr);
    }

    /// Allocates a u32 in memory with 8 byte allignment
    pub fn alloc_u32(&mut self) -> u32 {
        let p = self.free_pos();
        self.set_free_pos(p + 8);
        p
    }

    /// Writes a u32 to the specified memory offset
    pub fn write_u32(&mut self, ptr: usize, num: u32) {
        let store = self.store.read().unwrap();
        let view = self.memory.view(&*store);

        view.write(ptr as u64, &num.to_le_bytes()).unwrap();
    }

    /// Reads a u32 from the specified memory offset
    pub fn read_u32(&self, ptr: usize) -> u32 {
        let store = self.store.read().unwrap();
        let view = self.memory.view(&*store);

        let mut bytes = [0; 4];
        view.read(ptr as u64, &mut bytes).unwrap();

        u32::from_le_bytes(bytes)
    }

    /// Allocates `self.limbs_32 * 4 + 8` bytes in the memory
    pub fn alloc_fr(&mut self) -> u32 {
        let p = self.free_pos();
        self.set_free_pos(p + self.limbs_32 as u32 * 4 + 8);
        p
    }

    /// Writes a Field Element to memory at the specified offset, truncating
    /// to smaller u32 types if needed and adjusting the sign via 2s complement
    pub fn write_fr(&mut self, ptr: usize, fr: &BigInt) -> Result<()> {
        if fr < &self.short_max && fr > &self.short_min {
            if fr >= &BigInt::zero() {
                self.write_short_positive(ptr, fr)?;
            } else {
                self.write_short_negative(ptr, fr)?;
            }
        } else {
            self.write_long_normal(ptr, fr)?;
        }

        Ok(())
    }

    /// Reads a Field Element from the memory at the specified offset
    pub fn read_fr(&self, ptr: usize) -> Result<BigInt> {
        let store = self.store.read().unwrap();
        let view = self.memory.view(&*store);

        let res = if view.read_u8(ptr as u64 + 4 + 3)? & 0x80 != 0 {
            let mut num = self.read_big(ptr + 8, self.limbs_32)?;
            if view.read_u8(ptr as u64 + 4 + 3)? & 0x40 != 0 {
                num = (num * &self.r_inv) % &self.prime
            }
            num
        } else if view.read_u8(ptr as u64 + 3)? & 0x40 != 0 {
            let mut num = self.read_u32(ptr).into();
            // handle small negative
            num -= BigInt::from(0x100000000i64);
            num
        } else {
            self.read_u32(ptr).into()
        };

        Ok(res)
    }

    fn write_short_positive(&mut self, ptr: usize, fr: &BigInt) -> Result<()> {
        let num = fr.to_i32().expect("not a short positive");
        self.write_u32(ptr, num as u32);
        self.write_u32(ptr + 4, 0);
        Ok(())
    }

    fn write_short_negative(&mut self, ptr: usize, fr: &BigInt) -> Result<()> {
        // 2s complement
        let num = fr - &self.short_min;
        let num = num - &self.short_max;
        let num = num + BigInt::from(0x0001_0000_0000i64);

        let num = num
            .to_u32()
            .expect("could not cast as u32 (should never happen)");

        self.write_u32(ptr, num);
        self.write_u32(ptr + 4, 0);
        Ok(())
    }

    fn write_long_normal(&mut self, ptr: usize, fr: &BigInt) -> Result<()> {
        self.write_u32(ptr, 0);
        self.write_u32(ptr + 4, i32::MIN as u32); // 0x80000000
        self.write_big(ptr + 8, fr)?;
        Ok(())
    }

    fn write_big(&self, ptr: usize, num: &BigInt) -> Result<()> {
        let store = self.store.read().unwrap();
        let view = self.memory.view(&*store);

        // TODO: How do we handle negative bignums?
        let (_, num) = num.clone().into_parts();
        let num = BigInteger256::try_from(num).unwrap();

        view.write(ptr as u64, &num.to_bytes_le())
            .map_err(Into::into)
    }

    /// Reads `limbs_32 * 32` bytes from the specified memory offset in a Big Integer
    pub fn read_big(&self, ptr: usize, limbs_32: usize) -> Result<BigInt> {
        let store = self.store.read().unwrap();
        let view = self.memory.view(&*store);
        let buf = view.copy_range_to_vec(ptr as u64..(ptr + limbs_32 * 32) as u64)?;

        // TODO: Is there a better way to read big integers?
        let big = BigInteger256::deserialize_uncompressed(buf.as_slice()).unwrap();
        let big = BigUint::from(big);
        Ok(big.into())
    }
}

// TODO: Figure out how to read / write numbers > u32
// circom-witness-calculator: Wasm + Memory -> expose BigInts so that they can be consumed by any proof system
// ark-circom:
// 1. can read zkey
// 2. can generate witness from inputs
// 3. can generate proofs
// 4. can serialize proofs in the desired format
#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::ToPrimitive;
    use std::str::FromStr;
    use wasmer::{MemoryType, Store};

    fn safe_memory_testing_context() -> SafeMemory {
        let store = Arc::new(RwLock::new(Store::default()));
        let mut store_write = store.write().unwrap();

        let memory = Memory::new(&mut store_write, MemoryType::new(1, None, false)).unwrap();
        drop(store_write);

        SafeMemory::new(
            store,
            memory,
            2,
            BigInt::from_str(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617",
            )
            .unwrap(),
        )
    }

    #[test]
    fn i32_bounds() {
        let mem = safe_memory_testing_context();
        let i32_max = i32::MAX as i64 + 1;
        assert_eq!(mem.short_min.to_i64().unwrap(), -i32_max);
        assert_eq!(mem.short_max.to_i64().unwrap(), i32_max);
    }

    #[test]
    fn read_write_32() {
        let mut mem = safe_memory_testing_context();
        let num = u32::MAX;

        let inp = mem.read_u32(0);
        assert_eq!(inp, 0);

        mem.write_u32(0, num);
        let inp = mem.read_u32(0);
        assert_eq!(inp, num);
    }

    #[test]
    fn read_write_fr_small_positive() {
        read_write_fr(BigInt::from(1_000_000));
    }

    #[test]
    fn read_write_fr_small_negative() {
        read_write_fr(BigInt::from(-1_000_000));
    }

    #[test]
    fn read_write_fr_big_positive() {
        read_write_fr(BigInt::from(500000000000i64));
    }

    // TODO: How should this be handled?
    #[test]
    #[ignore]
    fn read_write_fr_big_negative() {
        read_write_fr(BigInt::from_str("-500000000000").unwrap())
    }

    fn read_write_fr(num: BigInt) {
        let mut mem = safe_memory_testing_context();
        mem.write_fr(0, &num).unwrap();
        let res = mem.read_fr(0).unwrap();
        assert_eq!(res, num);
    }
}
