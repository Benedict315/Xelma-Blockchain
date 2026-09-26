// SPDX-License-Identifier: MIT
//! Minimal contract errors required by settlement math when compiled in the replay crate.

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    Overflow,
    InvalidPrice,
    PayoutOverflow,
}
