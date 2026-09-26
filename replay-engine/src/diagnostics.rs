// SPDX-License-Identifier: MIT
//! Mismatch diagnostics when live settlement and replay diverge.

use crate::engine::ReplayResult;
use crate::transcript::{OutcomeKind, RoundTranscript};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MismatchDiagnostic {
    pub field: String,
    pub expected: String,
    pub replayed: String,
}

pub fn compare_replay(
    transcript: &RoundTranscript,
    replay: &ReplayResult,
) -> Vec<MismatchDiagnostic> {
    let mut out = Vec::new();
    let expected = &transcript.expected;

    if expected.archive_status != replay.archive_status {
        out.push(MismatchDiagnostic {
            field: "archive_status".into(),
            expected: format!("{:?}", expected.archive_status),
            replayed: format!("{:?}", replay.archive_status),
        });
    }

    if expected.total_fee != replay.total_fee {
        out.push(MismatchDiagnostic {
            field: "total_fee".into(),
            expected: expected.total_fee.to_string(),
            replayed: replay.total_fee.to_string(),
        });
    }

    if expected.payouts.len() != replay.payouts.len() {
        out.push(MismatchDiagnostic {
            field: "payouts.len".into(),
            expected: expected.payouts.len().to_string(),
            replayed: replay.payouts.len().to_string(),
        });
        return out;
    }

    for (exp, rep) in expected.payouts.iter().zip(replay.payouts.iter()) {
        if exp.index != rep.index {
            out.push(MismatchDiagnostic {
                field: format!("payouts[{}].index", exp.index),
                expected: exp.index.to_string(),
                replayed: rep.index.to_string(),
            });
        }
        if exp.payout != rep.payout {
            out.push(MismatchDiagnostic {
                field: format!("payouts[{}].payout", exp.index),
                expected: exp.payout.to_string(),
                replayed: rep.payout.to_string(),
            });
        }
        if exp.outcome != rep.outcome {
            out.push(MismatchDiagnostic {
                field: format!("payouts[{}].outcome", exp.index),
                expected: format!("{:?}", exp.outcome),
                replayed: format!("{:?}", rep.outcome),
            });
        }
    }

    out
}

pub fn assert_live_matches_replay(
    transcript: &RoundTranscript,
    replay: &ReplayResult,
) -> Result<(), Vec<MismatchDiagnostic>> {
    let mismatches = compare_replay(transcript, replay);
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches)
    }
}

pub fn outcome_from_flags(is_winner: bool, is_refund: bool, void: bool) -> OutcomeKind {
    if void {
        OutcomeKind::Void
    } else if is_refund {
        OutcomeKind::Refund
    } else if is_winner {
        OutcomeKind::Win
    } else {
        OutcomeKind::Loss
    }
}
