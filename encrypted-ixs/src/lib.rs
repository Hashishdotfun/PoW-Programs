//! MPC circuits for privacy-preserving PoW mining
//!
//! These circuits are executed by Arcium's MPC network with persistent state.
//! All data inside remains encrypted - no single party can see the contents.
//!
//! IMPORTANT: arcis 0.9.2 does NOT support ordered comparisons (>, >=, <, <=)
//! in circuit compilation. Only == and != work. Balance validation must happen
//! on-chain, not in the MPC circuit. The circuit handles privacy (encryption)
//! while the on-chain program handles validation (sufficient balance, etc.).
//!
//! Two separate encrypted states per miner:
//! - MinerState: SOL balance (for protocol fees)
//! - MinerStateToken: HASHISH token balance (mining rewards)

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

    /// Persistent state for a miner's encrypted SOL balance
    #[derive(Clone)]
    pub struct MinerState {
        /// Current SOL balance in lamports
        pub balance: u64,
        /// Transaction nonce (anti-replay)
        pub nonce: u64,
        /// Reserved for future use
        pub reserved: u64,
    }

    /// Persistent state for a miner's encrypted HASHISH token balance
    #[derive(Clone)]
    pub struct MinerStateToken {
        /// Current HASHISH token balance (smallest unit, 9 decimals)
        pub token_balance: u64,
        /// Transaction nonce (anti-replay)
        pub nonce: u64,
        /// Reserved for future use
        pub reserved: u64,
    }

    // =========================================================================
    // SOL BALANCE RESULTS
    // =========================================================================

    /// Result of depositing SOL to miner's balance
    #[derive(Clone)]
    pub struct DepositFeeResult {
        pub new_balance: u64,
        pub success: bool,
    }

    /// Result of mining a block (deducting protocol fee)
    #[derive(Clone)]
    pub struct MineBlockResult {
        pub new_balance: u64,
        pub fee_deducted: u64,
        pub success: bool,
    }

    /// Result of withdrawing SOL to a destination
    #[derive(Clone)]
    pub struct WithdrawFeeResult {
        pub destination: [u64; 4],
        pub amount: u64,
        pub new_balance: u64,
        pub success: bool,
    }

    /// Result of checking miner SOL balance
    #[derive(Clone)]
    pub struct CheckBalanceResult {
        pub balance: u64,
        pub nonce: u64,
        pub success: bool,
    }

    // =========================================================================
    // TOKEN BALANCE RESULTS
    // =========================================================================

    /// Result of depositing HASHISH tokens to miner's token balance
    #[derive(Clone)]
    pub struct DepositTokenResult {
        pub new_token_balance: u64,
        pub success: bool,
    }

    /// Result of withdrawing HASHISH tokens to a destination
    #[derive(Clone)]
    pub struct WithdrawTokenResult {
        pub destination: [u64; 4],
        pub amount: u64,
        pub new_token_balance: u64,
        pub success: bool,
    }

    // =========================================================================
    // SOL BALANCE INSTRUCTIONS
    // =========================================================================

    /// Deposit SOL to miner's encrypted balance
    #[instruction]
    pub fn deposit_fee(
        amount: Enc<Shared, u64>,
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, DepositFeeResult> {
        let deposit_amount = amount.to_arcis();
        let state = current_state.to_arcis();

        let result = DepositFeeResult {
            new_balance: state.balance + deposit_amount,
            success: true,
        };

        current_state.owner.from_arcis(result)
    }

    /// Mine a block - deduct protocol fee from encrypted SOL balance
    #[instruction]
    pub fn mine_block(
        protocol_fee: Enc<Shared, u64>,
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, MineBlockResult> {
        let fee = protocol_fee.to_arcis();
        let state = current_state.to_arcis();

        let result = MineBlockResult {
            new_balance: state.balance - fee,
            fee_deducted: fee,
            success: true,
        };

        protocol_fee.owner.from_arcis(result)
    }

    /// Withdraw SOL to a destination address
    #[instruction]
    pub fn withdraw_fee(
        amount: Enc<Shared, u64>,
        destination: Enc<Shared, EncryptedDestination>,
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, WithdrawFeeResult> {
        let withdraw_amount = amount.to_arcis();
        let dest = destination.to_arcis();
        let state = current_state.to_arcis();

        let result = WithdrawFeeResult {
            destination: dest,
            amount: withdraw_amount,
            new_balance: state.balance - withdraw_amount,
            success: true,
        };

        current_state.owner.from_arcis(result)
    }

    /// Check miner's current SOL balance
    #[instruction]
    pub fn check_miner_balance(
        current_state: Enc<Shared, MinerState>,
    ) -> Enc<Shared, CheckBalanceResult> {
        let state = current_state.to_arcis();

        let nonce_with_reserved = state.nonce + state.reserved;

        let result = CheckBalanceResult {
            balance: state.balance,
            nonce: nonce_with_reserved,
            success: true,
        };

        current_state.owner.from_arcis(result)
    }

    // =========================================================================
    // TOKEN BALANCE INSTRUCTIONS
    // =========================================================================

    /// Deposit HASHISH tokens to miner's encrypted token balance
    /// Called after mining to credit the reward, or for manual deposits
    #[instruction]
    pub fn deposit_token(
        amount: Enc<Shared, u64>,
        current_token_state: Enc<Shared, MinerStateToken>,
    ) -> Enc<Shared, DepositTokenResult> {
        let deposit_amount = amount.to_arcis();
        let state = current_token_state.to_arcis();

        let result = DepositTokenResult {
            new_token_balance: state.token_balance + deposit_amount,
            success: true,
        };

        current_token_state.owner.from_arcis(result)
    }

    /// Withdraw HASHISH tokens to a destination address
    /// Balance validation is done on-chain before calling this circuit
    #[instruction]
    pub fn withdraw_token(
        amount: Enc<Shared, u64>,
        destination: Enc<Shared, EncryptedDestination>,
        current_token_state: Enc<Shared, MinerStateToken>,
    ) -> Enc<Shared, WithdrawTokenResult> {
        let withdraw_amount = amount.to_arcis();
        let dest = destination.to_arcis();
        let state = current_token_state.to_arcis();

        let result = WithdrawTokenResult {
            destination: dest,
            amount: withdraw_amount,
            new_token_balance: state.token_balance - withdraw_amount,
            success: true,
        };

        current_token_state.owner.from_arcis(result)
    }
}
