#![no_main]

use core::ops::{Rem, Shl};

use arbitrary::{Arbitrary, Result, Unstructured};
use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer::optimize;
use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use num_traits::identities::One;

use bitvm::bigint::{std::bigint_verify_output_script, U254, U256, U64};
use bitvm::execute_script_buf;
use bitvm_fuzz::{match_bigint_type, BigIntType, BIGINT_TYPE_LAST_INDEX, U384};

#[derive(Debug)]
pub struct BigIntConfig {
    pub value_a: Vec<u32>,
    pub value_b: Vec<u32>,
    pub bigint_type: BigIntType,
}

impl BigIntConfig {
    pub fn create_add_script(&self) -> Vec<u8> {
        let mut bytes = match_bigint_type!(self.bigint_type, push_u32_le, self.value_a.as_ref())
            .compile()
            .to_bytes();
        bytes.extend_from_slice(
            match_bigint_type!(self.bigint_type, push_u32_le, self.value_b.as_ref())
                .compile()
                .as_bytes(),
        );
        bytes.extend_from_slice(
            match_bigint_type!(self.bigint_type, add, 0, 1)
                .compile()
                .as_bytes(),
        ); // a + b
        bytes.extend_from_slice(
            match_bigint_type!(self.bigint_type, double, 0)
                .compile()
                .as_bytes(),
        ); // 2(a + b)

        let mut a = BigUint::from_slice(self.value_a.as_ref());
        let b = BigUint::from_slice(self.value_b.as_ref());
        let modulo = BigUint::one().shl(self.bigint_type.n_bits());
        a = (&a + b).rem(&modulo);
        a = (&a + &a).rem(&modulo);

        let push_answer = match_bigint_type!(self.bigint_type, push_u32_le, &a.to_u32_digits());
        bytes.extend_from_slice(push_answer.compile().as_bytes());

        bytes
    }
}

impl<'a> Arbitrary<'a> for BigIntConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let bigint_type = BigIntType::from_index(u.int_in_range(0..=BIGINT_TYPE_LAST_INDEX)?);
        let value_a = bigint_type.generate_arbitrary_bigint(u)?;
        let value_b = bigint_type.generate_arbitrary_bigint(u)?;

        Ok(BigIntConfig {
            value_a,
            value_b,
            bigint_type,
        })
    }
}

fuzz_target!(|message: BigIntConfig| {
    let mut bytes = message.create_add_script();
    bytes.extend_from_slice(
        bigint_verify_output_script(message.bigint_type.n_limbs())
            .compile()
            .as_bytes(),
    );

    let script = optimize(ScriptBuf::from_bytes(bytes));
    assert!(execute_script_buf(script).success);
});
