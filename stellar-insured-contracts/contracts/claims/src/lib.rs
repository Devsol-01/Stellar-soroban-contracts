use crate::dispute::Dispute;

impl ClaimsContract {
    pub fn raise_dispute(
        env: Env,
        claim_id: u64,
        raised_by: Address,
        reason: soroban_sdk::String,
    ) {
        raised_by.require_auth();

        let mut claim: Claim = env.storage().instance().get(&claim_id).unwrap();

        if claim.status != ClaimStatus::PendingSettlement {
            panic!("Claim not disputable");
        }

        let now = env.ledger().timestamp();
        let window_end = claim.dispute_window_end.unwrap();

        if now > window_end {
            panic!("Dispute window closed");
        }

        // DAO authorization check (simple allowlist)
        let dao_members: Vec<Address> =
            env.storage().instance().get(&"DAO_MEMBERS").unwrap();

        if !dao_members.contains(&raised_by) {
            panic!("Not DAO authorized");
        }

        claim.status = ClaimStatus::Disputed;
        env.storage().instance().set(&claim_id, &claim);

        let dispute = Dispute {
            claim_id,
            raised_by,
            reason,
            resolved: false,
        };

        env.storage().instance().set(&("DISPUTE", claim_id), &dispute);
    }
}
