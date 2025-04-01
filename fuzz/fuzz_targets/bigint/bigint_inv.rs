#![no_main]

use arbitrary::{Arbitrary, Result, Unstructured};
use bitcoin::ScriptBuf;
use bitcoin_script_stack::optimizer::optimize;
use bitvm::pseudo::push_to_stack;
use libfuzzer_sys::fuzz_target;
use num_bigint::BigUint;
use num_traits::Euclid;

use bitvm::bigint::{std::bigint_verify_output_script, U254, U256, U64};
use bitvm::execute_script_buf;
use bitvm_fuzz::{match_bigint_type, BigIntType, BIGINT_TYPE_LAST_INDEX, U384};

#[derive(Debug)]
pub struct BigIntConfig {
    pub value: Vec<u32>,
    pub bigint_type: BigIntType,
}

impl BigIntConfig {
    pub fn create_inv_script(&self) -> Vec<u8> {
        let mut bytes = match_bigint_type!(self.bigint_type, push_u32_le, self.value.as_ref())
            .compile()
            .to_bytes();
        let value = BigUint::from_slice(self.value.as_ref());

        bytes.extend_from_slice(
            match_bigint_type!(self.bigint_type, div3rem)
                .compile()
                .as_bytes(),
        );
        let (value, rem) = value.div_rem_euclid(&BigUint::from(3_u32));
        bytes.extend_from_slice(
            push_to_stack(rem.try_into().unwrap(), 1)
                .compile()
                .as_bytes(),
        );
        bytes.extend_from_slice(&[0x88]); // OP_EQUALVERIFY

        bytes.extend_from_slice(
            match_bigint_type!(self.bigint_type, div2rem)
                .compile()
                .as_bytes(),
        );
        let (value, rem) = value.div_rem_euclid(&BigUint::from(2_u32));
        bytes.extend_from_slice(
            push_to_stack(rem.try_into().unwrap(), 1)
                .compile()
                .as_bytes(),
        );
        bytes.extend_from_slice(&[0x88]); // OP_EQUALVERIFY

        let push_answer = match_bigint_type!(self.bigint_type, push_u32_le, &value.to_u32_digits());
        bytes.extend_from_slice(push_answer.compile().as_bytes());

        bytes
    }
}

impl<'a> Arbitrary<'a> for BigIntConfig {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let bigint_type = BigIntType::from_index(u.int_in_range(0..=BIGINT_TYPE_LAST_INDEX)?);
        let value = bigint_type.generate_arbitrary_bigint(u)?;

        Ok(BigIntConfig { value, bigint_type })
    }
}

fuzz_target!(|message: BigIntConfig| {
    let mut bytes = message.create_inv_script();
    bytes.extend_from_slice(
        bigint_verify_output_script(message.bigint_type.n_limbs())
            .compile()
            .as_bytes(),
    );
    let script = optimize(ScriptBuf::from_bytes(bytes));
    assert!(execute_script_buf(script).success);
});
