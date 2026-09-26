// SPDX-License-Identifier: MIT
//! Settlement math compiled from the contract source tree (same code path as live settlement).

#[path = "../../contracts/src/settlement_math.rs"]
mod inner;

pub use inner::*;
