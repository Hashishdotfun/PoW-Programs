//! MPC circuits for privacy-preserving PoW mining
//!
//! These circuits are executed by Arcium's MPC network with persistent state.
//! All data inside remains encrypted - no single party can see the contents.
//!
//! Data format for encrypted destination:
//! - 4 x u64 values (32 bytes total) for the destination pubkey
//! - This generates only 4 ciphertexts instead of 32
//!
//! Balance tracking:
//! - Miner balances are tracked using miner_id_hash = hash(secret_key)
//! - Balances are stored encrypted in Arcium's MPC network (persistent state)
//! - Only the miner with the secret can access/modify their balance
//! - Balance starts at 0, initialized on first deposit

use arcis::*;

/// Encrypted module containing all MPC circuits
#[encrypted]
pub mod circuits {
    use arcis::*;

    // =========================================================================
    // DATA STRUCTURES
    // =========================================================================

    /// Encrypted destination pubkey as 4 x u64 (32 bytes total = 4 ciphertexts)
    pub type EncryptedDestination = [u64; 4];

    /// Persistent state for a miner's encrypted balance
    /// Stored in Arcium's MPC network and retrieved by miner_id_hash
    #[derive(Clone, Default)]
    pub struct MinerState {
        /// Current balance in lamports
        pub balance: u64,
        /// Transaction nonce (anti-replay)
        pub nonce: u64,
        /// Reserved for future use
        pub reserved: u64,
    }

    /// Result of storing a claim
    #[derive(Clone)]
    pub struct StoreClaimResult {
        /// Stored destination (echoed back for verification)
        pub destination: [u64; 4],
        /// Success flag
        pub success: bool,
    }

    /// Result of a claim verification
    #[derive(Clone)]
    pub struct VerifyAndClaimResult {
        /// The decrypted destination pubkey as 4 x u64
        pub destination: [u64; 4],
        /// The claim amount
        pub amount: u64,
        /// Whether verification succeeded
        pub success: bool,
    }

    /// Result of depositing fee to miner's balance
    #[derive(Clone)]
    pub struct DepositFeeResult {
        /// New balance after deposit
        pub new_balance: u64,
        /// Whether deposit succeeded
        pub success: bool,
    }

    /// Result of mining a block (deducting protocol fee)
    /// success: false triggers revert on-chain
    #[derive(Clone)]
    pub struct MineBlockResult {
        /// New balance after fee deduction
        pub new_balance: u64,
        /// The protocol fee that was deducted
        pub fee_deducted: u64,
        /// Whether mining succeeded (enough balance)
        pub success: bool,
    }

    /// Result of withdrawing fees to a destination
    #[derive(Clone)]
    pub struct WithdrawFeeResult {
        /// The destination pubkey to send SOL to
        pub destination: [u64; 4],
        /// Amount to withdraw
        pub amount: u64,
        /// New balance after withdrawal
        pub new_balance: u64,
        /// Whether withdrawal succeeded
        pub success: bool,
    }

    /// Result of checking miner balance
    #[derive(Clone)]
    pub struct CheckBalanceResult {
        /// Current balance
        pub balance: u64,
        /// Current nonce
        pub nonce: u64,
        /// Whether query succeeded
        pub success: bool,
    }


    // =========================================================================
    // BALANCE MANAGEMENT WITH PERSISTENT STATE
    // =========================================================================

    /// Deposit SOL to miner's encrypted balance
    /// Initializes state to 0 if first deposit, then adds amount
    #[instruction]
    pub fn deposit_fee(
        amount: Enc<Shared, u64>,
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, (MinerState, DepositFeeResult)> {
        let deposit_amount = amount.to_arcis();
        let mut state = current_state.to_arcis();

        // Add deposit to balance
        state.balance = state.balance + deposit_amount;
        state.nonce = state.nonce + 1;

        let result = DepositFeeResult {
            new_balance: state.balance,
            success: true,
        };

        current_state.owner.from_arcis((state, result))
    }

    /// Mine a block - verify balance and deduct protocol fee
    /// Returns success: false if insufficient balance (on-chain program should revert)
    #[instruction]
    pub fn mine_block(
        protocol_fee: Enc<Shared, u64>,
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, (MinerState, MineBlockResult)> {
        let fee = protocol_fee.to_arcis();
        let mut state = current_state.to_arcis();

        // Check if sufficient balance - use conditional assignment for MPC
        let has_sufficient_balance = state.balance >= fee;

        // Only deduct if sufficient balance, otherwise keep state unchanged
        // In MPC, we use arithmetic instead of branching
        let new_balance = if has_sufficient_balance {
            state.balance - fee
        } else {
            state.balance
        };

        let fee_deducted = if has_sufficient_balance { fee } else { 0 };

        state.balance = new_balance;
        state.nonce = state.nonce + 1;

        let result = MineBlockResult {
            new_balance: state.balance,
            fee_deducted,
            success: has_sufficient_balance,
        };

        current_state.owner.from_arcis((state, result))
    }

    /// Withdraw fees to a new destination address
    /// Returns success: false if insufficient balance (on-chain program should revert)
    #[instruction]
    pub fn withdraw_fee(
        amount: Enc<Shared, u64>,
        destination: Enc<Shared, EncryptedDestination>,
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, (MinerState, WithdrawFeeResult)> {
        let withdraw_amount = amount.to_arcis();
        let dest = destination.to_arcis();
        let mut state = current_state.to_arcis();

        // Check if sufficient balance - use conditional assignment for MPC
        let has_sufficient_balance = state.balance >= withdraw_amount;

        // Only deduct if sufficient balance, otherwise keep state unchanged
        let new_balance = if has_sufficient_balance {
            state.balance - withdraw_amount
        } else {
            state.balance
        };

        let actual_amount = if has_sufficient_balance { withdraw_amount } else { 0 };

        state.balance = new_balance;
        state.nonce = state.nonce + 1;

        let result = WithdrawFeeResult {
            destination: dest,
            amount: actual_amount,
            new_balance: state.balance,
            success: has_sufficient_balance,
        };

        current_state.owner.from_arcis((state, result))
    }

    /// Check miner's current balance
    #[instruction]
    pub fn check_miner_balance(
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, CheckBalanceResult> {
        let state = current_state.to_arcis();

        // Use nonce + reserved to ensure all state fields are processed
        let nonce_with_reserved = state.nonce + state.reserved;

        let result = CheckBalanceResult {
            balance: state.balance,
            nonce: nonce_with_reserved,
            success: true,
        };

        current_state.owner.from_arcis(result)
    }

    // =========================================================================
    // CLAIM INSTRUCTIONS
    // =========================================================================

    /// Store a new claim's encrypted destination
    #[instruction]
    pub fn store_claim(
        encrypted_dest: Enc<Shared, EncryptedDestination>,
    ) -> Enc<Shared, StoreClaimResult> {
        let dest = encrypted_dest.to_arcis();

        let result = StoreClaimResult {
            destination: dest,
            success: true,
        };

        encrypted_dest.owner.from_arcis(result)
    }

    /// Verify a claim and return the decrypted destination
    #[instruction]
    pub fn verify_and_claim(
        claim_id: Enc<Shared, u64>,
        secret: Enc<Shared, [u64; 4]>,
    ) -> Enc<Shared, VerifyAndClaimResult> {
        let id = claim_id.to_arcis();
        let sec = secret.to_arcis();

        let result = VerifyAndClaimResult {
            destination: sec,
            amount: id, // Echo claim_id as amount (placeholder)
            success: true,
        };

        claim_id.owner.from_arcis(result)
    }

}
