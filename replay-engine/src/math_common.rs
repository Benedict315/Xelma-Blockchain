// SPDX-License-Identifier: MIT
//! Checked payout arithmetic — mirrors `contracts/src/math_common.rs`.

use crate::errors::ContractError;

pub const BPS_DENOMINATOR: i128 = 10_000;

#[inline(always)]
pub fn payout_add(a: i128, b: i128) -> Result<i128, ContractError> {
    a.checked_add(b).ok_or(ContractError::PayoutOverflow)
}

#[inline(always)]
pub fn payout_mul(a: i128, b: i128) -> Result<i128, ContractError> {
    a.checked_mul(b).ok_or(ContractError::PayoutOverflow)
}
