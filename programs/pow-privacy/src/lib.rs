// Stops Rust Analyzer complaining about missing configs
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

pub mod constants;
pub mod errors;
pub mod state;
pub mod instructions;

use instructions::*;
pub use errors::ErrorCode;

declare_id!("CUsP6AJxG7VyEP2dR1LfzX7KDsn7FiWDPgMxWtUUdmkg");

/// Helper function to convert [u64; 4] to [u8; 32]
pub fn u64_array_to_bytes(arr: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, val) in arr.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&val.to_le_bytes());
    }
    bytes
}

// Use #[arcium_program] which extends #[program] with callback handling
#[arcium_program]
pub mod pow_privacy {
    use super::*;
    use crate::constants::*;
    #[allow(unused_imports)]
    use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

    // Off-chain circuit configuration
    use arcium_client::idl::arcium::types::{CircuitSource, OffChainCircuitSource};
    use arcium_macros::circuit_hash;

    // Off-chain circuit URLs (raw GitHub URLs for direct access)
    const DEPOSIT_FEE_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/deposit_fee.arcis";
    const MINE_BLOCK_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/mine_block.arcis";
    const WITHDRAW_FEE_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/withdraw_fee.arcis";
    const CHECK_BALANCE_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/check_miner_balance.arcis";
    const DEPOSIT_TOKEN_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/deposit_token.arcis";
    const WITHDRAW_TOKEN_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/withdraw_token.arcis";

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// Initialize the privacy protocol with shared vaults
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize::handler(ctx)
    }

    /// Initialize missing vault PDAs (shared_token_vault) when privacy_config already exists
    pub fn initialize_vaults(ctx: Context<InitializeVaults>) -> Result<()> {
        instructions::initialize_vaults::handler(ctx)
    }

    // =========================================================================
    // COMPUTATION DEFINITION INITIALIZATION
    // =========================================================================

    /// Initialize deposit_fee computation definition (off-chain circuit)
    pub fn init_deposit_fee_comp_def(ctx: Context<InitDepositFeeCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: DEPOSIT_FEE_URL.to_string(),
                hash: circuit_hash!("deposit_fee"),
            })),
            None,
        )?;
        Ok(())
    }

    /// Initialize mine_block computation definition (off-chain circuit)
    pub fn init_mine_block_comp_def(ctx: Context<InitMineBlockCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: MINE_BLOCK_URL.to_string(),
                hash: circuit_hash!("mine_block"),
            })),
            None,
        )?;
        Ok(())
    }

    /// Initialize withdraw_fee computation definition (off-chain circuit)
    pub fn init_withdraw_fee_comp_def(ctx: Context<InitWithdrawFeeCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: WITHDRAW_FEE_URL.to_string(),
                hash: circuit_hash!("withdraw_fee"),
            })),
            None,
        )?;
        Ok(())
    }

    /// Initialize check_miner_balance computation definition (off-chain circuit)
    pub fn init_check_balance_comp_def(ctx: Context<InitCheckBalanceCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: CHECK_BALANCE_URL.to_string(),
                hash: circuit_hash!("check_miner_balance"),
            })),
            None,
        )?;
        Ok(())
    }

    /// Initialize deposit_token computation definition (off-chain circuit)
    pub fn init_deposit_token_comp_def(ctx: Context<InitDepositTokenCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: DEPOSIT_TOKEN_URL.to_string(),
                hash: circuit_hash!("deposit_token"),
            })),
            None,
        )?;
        Ok(())
    }

    /// Initialize withdraw_token computation definition (off-chain circuit)
    pub fn init_withdraw_token_comp_def(ctx: Context<InitWithdrawTokenCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: WITHDRAW_TOKEN_URL.to_string(),
                hash: circuit_hash!("withdraw_token"),
            })),
            None,
        )?;
        Ok(())
    }

    // =========================================================================
    // BLOCK SUBMISSION (Relayer)
    // =========================================================================

    /// Relayer submits a block with encrypted data directly as parameters
    /// Verifies PoW, queues MPC computation (mine_block) to deduct protocol fee,
    /// then CPIs to pow-protocol to mint tokens
    ///
    /// # Arguments
    /// * `computation_offset` - Arcium computation offset
    /// * `nonce` - The PoW nonce found by miner
    /// * `client_pubkey` - x25519 public key for Arcium decryption
    /// * `encryption_nonce` - Nonce used with RescueCipher
    /// * `encrypted_current_state` - Encrypted miner SOL state (3 x 32 bytes)
    pub fn submit_block_private(
        ctx: Context<SubmitBlockPrivate>,
        computation_offset: u64,
        nonce: u128,
        client_pubkey: [u8; 32],
        encryption_nonce: u128,
        encrypted_current_state: [[u8; 32]; 3],
    ) -> Result<()> {
        instructions::submit_block_private::handler(
            ctx,
            computation_offset,
            nonce,
            client_pubkey,
            encryption_nonce,
            encrypted_current_state,
        )
    }

    // =========================================================================
    // SOL BALANCE MANAGEMENT (Private)
    // =========================================================================

    /// Create a deposit buffer with encrypted amount and current state (Step 1)
    pub fn create_deposit_buffer(
        ctx: Context<CreateDepositBuffer>,
        encrypted_amount: [u8; 32],
        encrypted_current_state: [[u8; 32]; 3],
        client_pubkey: [u8; 32],
        encryption_nonce: u128,
        amount: u64,
    ) -> Result<()> {
        instructions::create_deposit_buffer::handler(
            ctx,
            encrypted_amount,
            encrypted_current_state,
            client_pubkey,
            encryption_nonce,
            amount,
        )
    }

    /// Execute deposit with MPC balance update (Step 2)
    pub fn deposit_private(
        ctx: Context<DepositPrivate>,
        computation_offset: u64,
    ) -> Result<()> {
        instructions::deposit_private::handler(ctx, computation_offset)
    }

    /// Create a withdraw buffer with encrypted data (Step 1)
    pub fn create_withdraw_buffer(
        ctx: Context<CreateWithdrawBuffer>,
        encrypted_amount: [u8; 32],
        encrypted_destination: [[u8; 32]; 4],
        encrypted_current_state: [[u8; 32]; 3],
        client_pubkey: [u8; 32],
        encryption_nonce: u128,
        amount: u64,
    ) -> Result<()> {
        instructions::create_withdraw_buffer::handler(
            ctx,
            encrypted_amount,
            encrypted_destination,
            encrypted_current_state,
            client_pubkey,
            encryption_nonce,
            amount,
        )
    }

    /// Execute withdrawal with MPC verification (Step 2)
    pub fn withdraw_private(
        ctx: Context<WithdrawPrivate>,
        computation_offset: u64,
    ) -> Result<()> {
        instructions::withdraw_private::handler(ctx, computation_offset)
    }

    // =========================================================================
    // HASHISH TOKEN BALANCE MANAGEMENT (Private)
    // =========================================================================

    /// Create a deposit token buffer with encrypted amount and current token state (Step 1)
    pub fn create_deposit_token_buffer(
        ctx: Context<CreateDepositTokenBuffer>,
        encrypted_amount: [u8; 32],
        encrypted_current_token_state: [[u8; 32]; 3],
        client_pubkey: [u8; 32],
        encryption_nonce: u128,
        amount: u64,
    ) -> Result<()> {
        instructions::create_deposit_token_buffer::handler(
            ctx,
            encrypted_amount,
            encrypted_current_token_state,
            client_pubkey,
            encryption_nonce,
            amount,
        )
    }

    /// Execute token deposit with MPC balance update (Step 2)
    pub fn deposit_token_private(
        ctx: Context<DepositTokenPrivate>,
        computation_offset: u64,
    ) -> Result<()> {
        instructions::deposit_token_private::handler(ctx, computation_offset)
    }

    /// Create a withdraw token buffer with encrypted data (Step 1)
    pub fn create_withdraw_token_buffer(
        ctx: Context<CreateWithdrawTokenBuffer>,
        encrypted_amount: [u8; 32],
        encrypted_destination: [[u8; 32]; 4],
        encrypted_current_token_state: [[u8; 32]; 3],
        client_pubkey: [u8; 32],
        encryption_nonce: u128,
        amount: u64,
    ) -> Result<()> {
        instructions::create_withdraw_token_buffer::handler(
            ctx,
            encrypted_amount,
            encrypted_destination,
            encrypted_current_token_state,
            client_pubkey,
            encryption_nonce,
            amount,
        )
    }

    /// Execute token withdrawal with MPC verification (Step 2)
    pub fn withdraw_token_private(
        ctx: Context<WithdrawTokenPrivate>,
        computation_offset: u64,
    ) -> Result<()> {
        instructions::withdraw_token_private::handler(ctx, computation_offset)
    }

    /// Execute the token transfer after MPC callback approved (Step 3)
    pub fn execute_withdraw_token(
        ctx: Context<ExecuteWithdrawToken>,
    ) -> Result<()> {
        instructions::execute_withdraw_token::handler(ctx)
    }

    // =========================================================================
    // UTILITY
    // =========================================================================

    /// Deposit SOL into the shared vault (for fees) - Legacy simple deposit
    pub fn deposit_fee(ctx: Context<DepositFee>, amount: u64) -> Result<()> {
        instructions::deposit_fee::handler(ctx, amount)
    }

    // =========================================================================
    // ARCIUM MPC CALLBACKS
    // =========================================================================

    /// Callback for deposit_fee MPC computation
    /// Called by Arcium when the SOL balance update MPC completes
    #[arcium_callback(encrypted_ix = "deposit_fee")]
    pub fn deposit_fee_callback(
        ctx: Context<DepositFeeCallback>,
        output: SignedComputationOutputs<DepositFeeOutput>,
    ) -> Result<()> {
        // Verify the BLS signature on the computation output
        let _verified_output = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        // Mark buffer as processed
        ctx.accounts.deposit_buffer.is_used = true;

        msg!("Deposit fee callback: balance updated successfully");
        Ok(())
    }

    /// Callback for mine_block MPC computation
    /// Called by Arcium when the balance verification and deduction MPC completes
    #[arcium_callback(encrypted_ix = "mine_block")]
    pub fn mine_block_callback(
        ctx: Context<MineBlockCallback>,
        output: SignedComputationOutputs<MineBlockOutput>,
    ) -> Result<()> {
        // Verify the BLS signature on the computation output
        let _verified_output = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        msg!("Mine block callback: balance verified and fee deducted successfully");
        Ok(())
    }

    /// Callback for withdraw_fee MPC computation
    /// Called by Arcium when the SOL withdrawal verification MPC completes
    /// Transfers SOL to destination minus 0.5% fee to team wallet
    #[arcium_callback(encrypted_ix = "withdraw_fee")]
    pub fn withdraw_fee_callback(
        ctx: Context<WithdrawFeeCallback>,
        output: SignedComputationOutputs<WithdrawFeeOutput>,
    ) -> Result<()> {
        use anchor_lang::system_program::{transfer, Transfer};

        // Verify the BLS signature on the computation output
        let _verified_output = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        // Mark buffer as used and approved
        ctx.accounts.withdraw_buffer.is_used = true;
        ctx.accounts.withdraw_buffer.is_approved = true;

        // Get the verified destination and amount from the buffer
        let destination = ctx.accounts.destination.key();
        let gross_amount = ctx.accounts.withdraw_buffer.amount;

        ctx.accounts.withdraw_buffer.verified_destination = destination;
        ctx.accounts.withdraw_buffer.verified_amount = gross_amount;

        // Calculate fee (0.5% = 50 bps)
        let fee_bps = ctx.accounts.privacy_config.withdrawal_fee_bps as u64;
        let fee_amount = gross_amount
            .checked_mul(fee_bps)
            .and_then(|v| v.checked_div(BPS_DENOMINATOR))
            .ok_or(ErrorCode::FeeCalculationOverflow)?;
        let net_amount = gross_amount
            .checked_sub(fee_amount)
            .ok_or(ErrorCode::FeeCalculationOverflow)?;

        // Transfer SOL from shared vault using PDA signer
        let config_key = ctx.accounts.privacy_config.key();
        let fee_vault_bump = ctx.accounts.privacy_config.fee_vault_bump;
        let fee_vault_seeds: &[&[u8]] = &[
            SHARED_FEE_VAULT_SEED,
            config_key.as_ref(),
            &[fee_vault_bump],
        ];
        let signer_seeds: &[&[&[u8]]] = &[fee_vault_seeds];

        // Transfer net amount to destination
        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.shared_fee_vault.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                },
                signer_seeds,
            ),
            net_amount,
        )?;

        // Transfer fee to team wallet (if fee > 0 and team_wallet configured)
        if fee_amount > 0 && ctx.accounts.team_wallet.key() != Pubkey::default() {
            transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.system_program.to_account_info(),
                    Transfer {
                        from: ctx.accounts.shared_fee_vault.to_account_info(),
                        to: ctx.accounts.team_wallet.to_account_info(),
                    },
                    signer_seeds,
                ),
                fee_amount,
            )?;
        }

        emit!(crate::state::SolWithdrawProcessed {
            gross_amount,
            fee_amount,
            net_amount,
            destination,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!(
            "Withdraw fee callback: {} lamports net ({} fee) sent to {}",
            net_amount,
            fee_amount,
            destination
        );
        Ok(())
    }

    /// Callback for deposit_token MPC computation
    /// Called by Arcium when the HASHISH token balance update MPC completes
    #[arcium_callback(encrypted_ix = "deposit_token")]
    pub fn deposit_token_callback(
        ctx: Context<DepositTokenCallback>,
        output: SignedComputationOutputs<DepositTokenOutput>,
    ) -> Result<()> {
        // Verify the BLS signature on the computation output
        let _verified_output = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        // Mark buffer as processed
        ctx.accounts.deposit_token_buffer.is_used = true;

        msg!("Deposit token callback: token balance updated successfully");
        Ok(())
    }

    /// Callback for withdraw_token MPC computation
    /// Called by Arcium when the HASHISH token withdrawal verification MPC completes
    /// MPC callback for withdraw_token - only verifies BLS and marks buffer approved.
    /// The actual token transfers are done in execute_withdraw_token (separate instruction)
    /// to keep the callback account count low enough for Arcium MPC nodes.
    #[arcium_callback(encrypted_ix = "withdraw_token")]
    pub fn withdraw_token_callback(
        ctx: Context<WithdrawTokenCallback>,
        output: SignedComputationOutputs<WithdrawTokenOutput>,
    ) -> Result<()> {
        // Verify the BLS signature on the computation output
        let _verified_output = output.verify_output(
            ctx.accounts.cluster_account.as_ref(),
            &ctx.accounts.computation_account,
        )?;

        // Mark buffer as used and approved (transfers happen in execute_withdraw_token)
        ctx.accounts.withdraw_token_buffer.is_used = true;
        ctx.accounts.withdraw_token_buffer.is_approved = true;
        ctx.accounts.withdraw_token_buffer.verified_amount = ctx.accounts.withdraw_token_buffer.amount;

        msg!("Withdraw token callback: MPC verified, buffer approved for {} tokens",
            ctx.accounts.withdraw_token_buffer.amount);
        Ok(())
    }

    // =========================================================================
    // ACCOUNT STRUCTS (must be inside arcium_program module)
    // =========================================================================

    /// Initialize deposit_fee computation definition accounts
    #[init_computation_definition_accounts("deposit_fee", payer)]
    #[derive(Accounts)]
    pub struct InitDepositFeeCompDef<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,

        #[account(
            mut,
            address = derive_mxe_pda!()
        )]
        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: Initialized by Arcium program
        #[account(mut)]
        pub comp_def_account: UncheckedAccount<'info>,

        /// CHECK: address_lookup_table, checked by arcium program.
        #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
        pub address_lookup_table: UncheckedAccount<'info>,

        /// CHECK: lut_program is the Address Lookup Table program.
        #[account(address = LUT_PROGRAM_ID)]
        pub lut_program: UncheckedAccount<'info>,

        pub arcium_program: Program<'info, Arcium>,
        pub system_program: Program<'info, System>,
    }

    /// Initialize mine_block computation definition accounts
    #[init_computation_definition_accounts("mine_block", payer)]
    #[derive(Accounts)]
    pub struct InitMineBlockCompDef<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,

        #[account(
            mut,
            address = derive_mxe_pda!()
        )]
        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: Initialized by Arcium program
        #[account(mut)]
        pub comp_def_account: UncheckedAccount<'info>,

        /// CHECK: address_lookup_table, checked by arcium program.
        #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
        pub address_lookup_table: UncheckedAccount<'info>,

        /// CHECK: lut_program is the Address Lookup Table program.
        #[account(address = LUT_PROGRAM_ID)]
        pub lut_program: UncheckedAccount<'info>,

        pub arcium_program: Program<'info, Arcium>,
        pub system_program: Program<'info, System>,
    }

    /// Initialize withdraw_fee computation definition accounts
    #[init_computation_definition_accounts("withdraw_fee", payer)]
    #[derive(Accounts)]
    pub struct InitWithdrawFeeCompDef<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,

        #[account(
            mut,
            address = derive_mxe_pda!()
        )]
        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: Initialized by Arcium program
        #[account(mut)]
        pub comp_def_account: UncheckedAccount<'info>,

        /// CHECK: address_lookup_table, checked by arcium program.
        #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
        pub address_lookup_table: UncheckedAccount<'info>,

        /// CHECK: lut_program is the Address Lookup Table program.
        #[account(address = LUT_PROGRAM_ID)]
        pub lut_program: UncheckedAccount<'info>,

        pub arcium_program: Program<'info, Arcium>,
        pub system_program: Program<'info, System>,
    }

    /// Initialize check_miner_balance computation definition accounts
    #[init_computation_definition_accounts("check_miner_balance", payer)]
    #[derive(Accounts)]
    pub struct InitCheckBalanceCompDef<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,

        #[account(
            mut,
            address = derive_mxe_pda!()
        )]
        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: Initialized by Arcium program
        #[account(mut)]
        pub comp_def_account: UncheckedAccount<'info>,

        /// CHECK: address_lookup_table, checked by arcium program.
        #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
        pub address_lookup_table: UncheckedAccount<'info>,

        /// CHECK: lut_program is the Address Lookup Table program.
        #[account(address = LUT_PROGRAM_ID)]
        pub lut_program: UncheckedAccount<'info>,

        pub arcium_program: Program<'info, Arcium>,
        pub system_program: Program<'info, System>,
    }

    /// Initialize deposit_token computation definition accounts
    #[init_computation_definition_accounts("deposit_token", payer)]
    #[derive(Accounts)]
    pub struct InitDepositTokenCompDef<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,

        #[account(
            mut,
            address = derive_mxe_pda!()
        )]
        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: Initialized by Arcium program
        #[account(mut)]
        pub comp_def_account: UncheckedAccount<'info>,

        /// CHECK: address_lookup_table, checked by arcium program.
        #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
        pub address_lookup_table: UncheckedAccount<'info>,

        /// CHECK: lut_program is the Address Lookup Table program.
        #[account(address = LUT_PROGRAM_ID)]
        pub lut_program: UncheckedAccount<'info>,

        pub arcium_program: Program<'info, Arcium>,
        pub system_program: Program<'info, System>,
    }

    /// Initialize withdraw_token computation definition accounts
    #[init_computation_definition_accounts("withdraw_token", payer)]
    #[derive(Accounts)]
    pub struct InitWithdrawTokenCompDef<'info> {
        #[account(mut)]
        pub payer: Signer<'info>,

        #[account(
            mut,
            address = derive_mxe_pda!()
        )]
        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: Initialized by Arcium program
        #[account(mut)]
        pub comp_def_account: UncheckedAccount<'info>,

        /// CHECK: address_lookup_table, checked by arcium program.
        #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
        pub address_lookup_table: UncheckedAccount<'info>,

        /// CHECK: lut_program is the Address Lookup Table program.
        #[account(address = LUT_PROGRAM_ID)]
        pub lut_program: UncheckedAccount<'info>,

        pub arcium_program: Program<'info, Arcium>,
        pub system_program: Program<'info, System>,
    }

    // =========================================================================
    // CALLBACK ACCOUNT STRUCTS
    // =========================================================================

    /// Callback accounts for deposit_fee
    #[callback_accounts("deposit_fee")]
    #[derive(Accounts)]
    pub struct DepositFeeCallback<'info> {
        pub arcium_program: Program<'info, Arcium>,

        pub comp_def_account: Account<'info, ComputationDefinitionAccount>,

        pub mxe_account: Account<'info, MXEAccount>,

        /// CHECK: computation_account, passed to verify_output
        pub computation_account: UncheckedAccount<'info>,

        pub cluster_account: Account<'info, Cluster>,

        #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
        /// CHECK: instructions_sysvar
        pub instructions_sysvar: AccountInfo<'info>,

        // Custom accounts
        #[account(mut)]
        pub privacy_config: Account<'info, crate::state::PrivacyConfig>,

        #[account(mut)]
        pub deposit_buffer: Account<'info, crate::state::DepositBuffer>,
    }

    /// Callback accounts for mine_block
    /// Called after submit_block_private queues the MPC computation
    #[callback_accounts("mine_block")]
    #[derive(Accounts)]
    pub struct MineBlockCallback<'info> {
        pub arcium_program: Program<'info, Arcium>,

        pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: computation_account, passed to verify_output
        pub computation_account: UncheckedAccount<'info>,

        pub cluster_account: Box<Account<'info, Cluster>>,

        #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
        /// CHECK: instructions_sysvar
        pub instructions_sysvar: AccountInfo<'info>,

        // Custom accounts
        #[account(mut)]
        pub privacy_config: Box<Account<'info, crate::state::PrivacyConfig>>,
    }

    /// Callback accounts for withdraw_fee (SOL withdrawal with 0.5% fee)
    #[callback_accounts("withdraw_fee")]
    #[derive(Accounts)]
    pub struct WithdrawFeeCallback<'info> {
        pub arcium_program: Program<'info, Arcium>,

        pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: computation_account, passed to verify_output
        pub computation_account: UncheckedAccount<'info>,

        pub cluster_account: Box<Account<'info, Cluster>>,

        #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
        /// CHECK: instructions_sysvar
        pub instructions_sysvar: AccountInfo<'info>,

        // Custom accounts
        #[account(mut)]
        pub privacy_config: Box<Account<'info, crate::state::PrivacyConfig>>,

        #[account(mut)]
        pub withdraw_buffer: Box<Account<'info, crate::state::WithdrawBuffer>>,

        /// Shared fee vault (SOL source)
        /// CHECK: PDA verified by seeds
        #[account(mut)]
        pub shared_fee_vault: UncheckedAccount<'info>,

        /// Destination for the withdrawal (MPC-verified)
        /// CHECK: Verified by MPC output
        #[account(mut)]
        pub destination: UncheckedAccount<'info>,

        /// Team wallet for receiving withdrawal fees
        /// CHECK: Verified against privacy_config.team_wallet
        #[account(mut)]
        pub team_wallet: UncheckedAccount<'info>,

        pub system_program: Program<'info, System>,
    }

    /// Callback accounts for deposit_token
    #[callback_accounts("deposit_token")]
    #[derive(Accounts)]
    pub struct DepositTokenCallback<'info> {
        pub arcium_program: Program<'info, Arcium>,

        pub comp_def_account: Account<'info, ComputationDefinitionAccount>,

        pub mxe_account: Account<'info, MXEAccount>,

        /// CHECK: computation_account, passed to verify_output
        pub computation_account: UncheckedAccount<'info>,

        pub cluster_account: Account<'info, Cluster>,

        #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
        /// CHECK: instructions_sysvar
        pub instructions_sysvar: AccountInfo<'info>,

        // Custom accounts
        #[account(mut)]
        pub privacy_config: Account<'info, crate::state::PrivacyConfig>,

        #[account(mut)]
        pub deposit_token_buffer: Account<'info, crate::state::DepositTokenBuffer>,
    }

    /// Callback accounts for withdraw_token (HASHISH withdrawal with 0.5% fee)
    #[callback_accounts("withdraw_token")]
    #[derive(Accounts)]
    pub struct WithdrawTokenCallback<'info> {
        pub arcium_program: Program<'info, Arcium>,

        pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

        pub mxe_account: Box<Account<'info, MXEAccount>>,

        /// CHECK: computation_account, passed to verify_output
        pub computation_account: UncheckedAccount<'info>,

        pub cluster_account: Box<Account<'info, Cluster>>,

        #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
        /// CHECK: instructions_sysvar
        pub instructions_sysvar: AccountInfo<'info>,

        // Custom accounts (kept minimal for Arcium callback account limits)
        #[account(mut)]
        pub privacy_config: Box<Account<'info, crate::state::PrivacyConfig>>,

        #[account(mut)]
        pub withdraw_token_buffer: Box<Account<'info, crate::state::WithdrawTokenBuffer>>,
    }
}
