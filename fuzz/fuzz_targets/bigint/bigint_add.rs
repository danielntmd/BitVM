#![no_main]

use core::ops::{Rem, Shl};

use arbitrary::{Arbitrary, Result, Unstructured};
use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer::optimize;
use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use num_traits::identities::One;

use bitvm::execute_script_buf;
use bitvm::bigint::{std::bigint_verify_output_script, U254, U256, U64};
use bitvm_fuzz::{match_bigint_type, BigIntType, U384, BIGINT_TYPE_LAST_INDEX};

#[derive(Debug)]
pub struct BigIntConfig {
    pub a: Vec<u32>,
    pub b: Vec<u32>,
    pub c: Vec<u32>,
    pub bigint_type: BigIntType,
}

impl BigIntConfig {
    pub fn create_add_script(&self) -> Vec<u8> {
        let mut bytes = match_bigint_type!(self.bigint_type, push_u32_le, self.a.as_ref()).compile().to_bytes();
        bytes.extend_from_slice(match_bigint_type!(self.bigint_type, push_u32_le, self.b.as_ref()).compile().as_bytes());
        bytes.extend_from_slice(match_bigint_type!(self.bigint_type, push_u32_le, self.c.as_ref()).compile().as_bytes());
        
        bytes.extend_from_slice(match_bigint_type!(self.bigint_type, add, 2, 1).compile().as_bytes()); // a + b
        bytes.extend_from_slice(match_bigint_type!(self.bigint_type, double, 0).compile().as_bytes()); // 2(a + b)
        bytes.extend_from_slice(match_bigint_type!(self.bigint_type, add, 1, 0).compile().as_bytes()); // 2(a + b) + c
        bytes.extend_from_slice(match_bigint_type!(self.bigint_type, double, 0).compile().as_bytes()); // 2(2(a + b) + c)

        let mut a = BigUint::from_slice(self.a.as_ref());
        let b = BigUint::from_slice(self.b.as_ref());
        let c = BigUint::from_slice(self.c.as_ref());

        let modulo = BigUint::one().shl(self.bigint_type.n_bits());
        a = (a.clone() + b).rem(modulo.clone());
        a = (a.clone() + a).rem(modulo.clone());
        a = (a.clone() + c).rem(modulo.clone());
        a = (a.clone() + a).rem(modulo.clone()); 

        let push_answer = match_bigint_type!(self.bigint_type, push_u32_le, &a.to_u32_digits());
        bytes.extend_from_slice(push_answer.compile().as_bytes());

        bytes
    }
}

impl<'a> Arbitrary<'a> for BigIntConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let bigint_type = BigIntType::from_index(u.int_in_range(0..=BIGINT_TYPE_LAST_INDEX)?);
        let n_bits = bigint_type.n_bits();
        let n_limbs = n_bits.div_ceil(bigint_type.limb_size());
        let a = (0..n_limbs)
            .map(|_| u.arbitrary())
            .collect::<Result<Vec<u32>>>()?;
        let b = (0..n_limbs)
            .map(|_| u.arbitrary())
            .collect::<Result<Vec<u32>>>()?;
        let c = (0..n_limbs)
            .map(|_| u.arbitrary())
            .collect::<Result<Vec<u32>>>()?;

        Ok(BigIntConfig {
            a,
            b, 
            c,
            bigint_type,
        })
    }
}

fuzz_target!(|message: BigIntConfig| {
    let mut bytes = message.create_add_script();
    bytes.extend_from_slice(
        bigint_verify_output_script(message.a.len() as u32)
            .compile()
            .as_bytes(),
    );

    let script = optimize(ScriptBuf::from_bytes(bytes));
    assert!(execute_script_buf(script).success);
});
