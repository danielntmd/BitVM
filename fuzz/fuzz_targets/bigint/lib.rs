pub mod macros; 

use bitvm::bigint::{BigIntImpl, U254, U256, U64};

pub type U384 = BigIntImpl<384, 29>;

pub const BIGINT_TYPE_LAST_INDEX: u32 = 3;

#[derive(Debug)]
pub enum BigIntType {
    U64(U64),
    U254(U254),
    U256(U256),
    U384(U384), // We use 256bit (BN254), but test for others (e.g. BLS12-381)
}

impl BigIntType {
    pub fn from_index(idx: u32) -> Self {
        match idx {
            0 => Self::U64(U64 {}),
            1 => Self::U254(U254 {}),
            2 => Self::U256(U256 {}),
            3 => Self::U384(U384 {}),
            _ => panic!("Invalid BigIntType index"),
        }
    }

    pub fn n_bits(&self) -> u32 {
        match self {
            BigIntType::U64(_) => U64::N_BITS,
            BigIntType::U254(_) => U254::N_BITS,
            BigIntType::U256(_) => U256::N_BITS,
            BigIntType::U384(_) => U384::N_BITS,
        }
    }

    pub fn limb_size(&self) -> u32 {
        match self {
            BigIntType::U64(_) => U64::LIMB_SIZE,
            BigIntType::U254(_) => U254::LIMB_SIZE,
            BigIntType::U256(_) => U256::LIMB_SIZE,
            BigIntType::U384(_) => U384::LIMB_SIZE,
        }
    }
}
