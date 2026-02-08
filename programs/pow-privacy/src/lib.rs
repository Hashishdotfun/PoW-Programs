// Stops Rust Analyzer complaining about missing configs
#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;

pub mod constants;
pub mod errors;
pub mod state;
pub mod instructions;

use instructions::*;
use state::PrivacyConfigArgs;
pub use errors::ErrorCode;

declare_id!("HHTo8FEGs8J7VfCD5yDg3ifoKozSaY2cbLfC2U418XjP");

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
    const STORE_CLAIM_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/store_claim.arcis";
    const VERIFY_AND_CLAIM_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/verify_and_claim.arcis";

    // New balance management circuits
    const DEPOSIT_FEE_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/deposit_fee.arcis";
    const MINE_BLOCK_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/mine_block.arcis";
    const WITHDRAW_FEE_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/withdraw_fee.arcis";
    const CHECK_BALANCE_URL: &str =
        "https://raw.githubusercontent.com/Antoninw3/arc/main/check_miner_balance.arcis";

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /// Initialize the privacy protocol with shared vaults
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        instructions::initialize::handler(ctx)
    }

    // =========================================================================
    // COMPUTATION DEFINITION INITIALIZATION
    // =========================================================================

    /// Initialize store_claim computation definition (off-chain circuit)
    pub fn init_store_claim_comp_def(ctx: Context<InitStoreClaimCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: STORE_CLAIM_URL.to_string(),
                hash: circuit_hash!("store_claim"),
            })),
            None,
        )?;
        Ok(())
    }

    /// Initialize verify_and_claim computation definition (off-chain circuit)
    pub fn init_verify_and_claim_comp_def(ctx: Context<InitVerifyAndClaimCompDef>) -> Result<()> {
        init_comp_def(
            ctx.accounts,
            Some(CircuitSource::OffChain(OffChainCircuitSource {
                source: VERIFY_AND_CLAIM_URL.to_string(),
                hash: circuit_hash!("verify_and_claim"),
            })),
            None,
        )?;
        Ok(())
    }

    /// Initialize deposit_fee computation definition (off-chain circuit)
    /// Used for adding SOL to miner's encrypted balance
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
    /// Used for verifying balance and deducting protocol fee during mining
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
    /// Used for withdrawing SOL from miner's encrypted balance
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
    /// Used for querying miner's encrypted balance
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

    // =========================================================================
    // CLAIM BUFFER (Multi-Transaction Flow)
    // =========================================================================

    /// Initialize a claim buffer with metadata (Transaction 1)
    /// Does NOT include the 1088 bytes of encrypted data yet
    pub fn init_claim_buffer(
        ctx: Context<InitClaimBuffer>,
        client_pubkey: [u8; 32],
        encryption_nonce: u128,
        secret_hash: [u8; 32],
    ) -> Result<()> {
        instructions::create_claim_buffer::handler_init(
            ctx,
            client_pubkey,
            encryption_nonce,
            secret_hash,
        )
    }

    /// Append encrypted bytes to the claim buffer (Transaction 2+)
    /// Can be called multiple times to fill the buffer with 1088 bytes
    pub fn append_claim_buffer(
        ctx: Context<AppendClaimBuffer>,
        data: Vec<u8>,
    ) -> Result<()> {
        instructions::create_claim_buffer::handler_append(ctx, data)
    }

    // =========================================================================
    // BLOCK SUBMISSION (Relayer)
    // =========================================================================

    /// Relayer submits a block with encrypted destination (Transaction 2)
    /// Reads from claim buffer and queues Arcium MPC computation
    pub fn submit_block_private(
        ctx: Context<SubmitBlockPrivate>,
        computation_offset: u64,
        nonce: u128,
    ) -> Result<()> {
        instructions::submit_block_private::handler(
            ctx,
            computation_offset,
            nonce,
        )
    }

    // =========================================================================
    // CLAIM REQUEST BUFFER (Single Transaction)
    // =========================================================================

    /// Initialize a claim request buffer with all data
    /// Now fits in a single transaction since we use [u64; 4] for secret (128 bytes)
    pub fn init_claim_request_buffer(
        ctx: Context<InitClaimRequestBuffer>,
        claim_id: u64,
        client_pubkey: [u8; 32],
        encryption_nonce: u128,
        secret: [u8; 32],
        encrypted_claim_id: [u8; 32],       // 1 ciphertext for u64
        encrypted_secret: [[u8; 32]; 4],    // 4 ciphertexts for [u64; 4]
    ) -> Result<()> {
        instructions::create_claim_request_buffer::handler_init(
            ctx,
            claim_id,
            client_pubkey,
            encryption_nonce,
            secret,
            encrypted_claim_id,
            encrypted_secret,
        )
    }

    // =========================================================================
    // CLAIM REWARDS (Miner)
    // =========================================================================

    /// Miner claims rewards by providing the secret (encrypted for MPC)
    /// Reads from claim request buffer and queues Arcium MPC computation
    ///
    /// Arguments:
    /// - computation_offset: Unique offset for this MPC computation
    pub fn claim_reward(
        ctx: Context<ClaimReward>,
        computation_offset: u64,
    ) -> Result<()> {
        instructions::claim_reward::handler(
            ctx,
            computation_offset,
        )
    }

    // =========================================================================
    // BALANCE MANAGEMENT (Private)
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
    // UTILITY
    // =========================================================================

    /// Deposit SOL into the shared vault (for fees) - Legacy simple deposit
    pub fn deposit_fee(ctx: Context<DepositFee>, amount: u64) -> Result<()> {
        instructions::deposit_fee::handler(ctx, amount)
    }

    /// Update protocol configuration (admin only)
    pub fn update_privacy_config(ctx: Context<UpdatePrivacyConfig>, args: PrivacyConfigArgs) -> Result<()> {
        instructions::admin::handler(ctx, args)
    }

    // =========================================================================
    // ARCIUM MPC CALLBACKS
    // =========================================================================

    /// Callback for store_claim MPC computation
    /// Called by Arcium when the MPC computation completes
    #[arcium_callback(encrypted_ix = "store_claim")]
    pub fn store_claim_callback(
        ctx: Context<StoreClaimCallback>,
        output: SignedComputationOutputs<StoreClaimOutput>,
    ) -> Result<()> {
        // Verify the BLS signature on the computation output
        let _verified_output = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        // Update the config to track the claim
        ctx.accounts.privacy_config.total_claims += 1;

        msg!("Store claim callback processed successfully");
        Ok(())
    }

    /// Callback for verify_and_claim MPC computation
    /// Called by Arcium when the verification MPC completes
    ///
    /// Note: The MPC verified the secret hash internally. The callback receives
    /// confirmation that verification passed. We use the claim data (stored on-chain)
    /// to determine the transfer amount, and the destination_token_account passed
    /// to perform the transfer.
    #[arcium_callback(encrypted_ix = "verify_and_claim")]
    pub fn verify_and_claim_callback(
        ctx: Context<VerifyAndClaimCallback>,
        output: SignedComputationOutputs<VerifyAndClaimOutput>,
    ) -> Result<()> {
        use anchor_spl::token_interface;

        // Verify the BLS signature on the computation output
        let _verified_output = output.verify_output(
            ctx.accounts.cluster_account.as_ref(),
            &ctx.accounts.computation_account,
        )?;

        msg!("Verify and claim callback: MPC output verified");

        // The MPC has verified the secret. Now we perform the transfer.
        // The amount comes from the claim (stored when submit_block_private was called)
        // The destination is the token account provided to this callback

        // Get the reward amount from the claim
        let amount = ctx.accounts.claim.amount;

        msg!("Transferring {} tokens to destination", amount);

        if amount > 0 {
            // Transfer tokens from shared vault to destination
            let config_key = ctx.accounts.privacy_config.key();
            let authority_bump = ctx.accounts.privacy_config.authority_bump;
            let authority_seeds: &[&[u8]] = &[
                PRIVACY_AUTHORITY_SEED,
                config_key.as_ref(),
                &[authority_bump],
            ];
            let signer_seeds: &[&[&[u8]]] = &[authority_seeds];

            let transfer_cpi_accounts = token_interface::TransferChecked {
                from: ctx.accounts.shared_token_vault.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.destination_token_account.to_account_info(),
                authority: ctx.accounts.privacy_authority.to_account_info(),
            };

            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                transfer_cpi_accounts,
                signer_seeds,
            );

            token_interface::transfer_checked(cpi_ctx, amount, ctx.accounts.mint.decimals)?;

            // Mark claim as processed
            ctx.accounts.claim.is_claimed = true;
            ctx.accounts.claim.claimed_at = Clock::get()?.unix_timestamp;

            msg!("Transfer complete! Claim marked as processed.");
        }

        Ok(())
    }

    /// Callback for deposit_fee MPC computation
    /// Called by Arcium when the balance update MPC completes
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
    /// 
    /// Note: If the miner had insufficient balance, the MPC circuit would have panicked
    /// and this callback would never be called (transaction reverts automatically)
    #[arcium_callback(encrypted_ix = "mine_block")]
    pub fn mine_block_callback(
        ctx: Context<MineBlockCallback>,
        output: SignedComputationOutputs<MineBlockOutput>,
    ) -> Result<()> {
        // Verify the BLS signature on the computation output
        // If this succeeds, it means the MPC ran successfully (balance was sufficient)
        let _verified_output = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        // Mark buffer as verified
        ctx.accounts.mine_block_buffer.balance_verified = true;
        ctx.accounts.mine_block_buffer.is_used = true;

        msg!("Mine block callback: balance verified and fee deducted successfully");
        Ok(())
    }

    /// Callback for withdraw_fee MPC computation
    /// Called by Arcium when the withdrawal verification MPC completes
    /// 
    /// Note: If the miner had insufficient balance, the MPC circuit would have panicked
    /// and this callback would never be called (transaction reverts automatically)
    #[arcium_callback(encrypted_ix = "withdraw_fee")]
    pub fn withdraw_fee_callback(
        ctx: Context<WithdrawFeeCallback>,
        output: SignedComputationOutputs<WithdrawFeeOutput>,
    ) -> Result<()> {
        use anchor_lang::system_program::{transfer, Transfer};

        // Verify the BLS signature on the computation output
        // If this succeeds, it means the MPC ran successfully (balance was sufficient)
        let _verified_output = output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        )?;

        // Mark buffer as used and approved
        ctx.accounts.withdraw_buffer.is_used = true;
        ctx.accounts.withdraw_buffer.is_approved = true;

        // Get the verified destination and amount from the buffer
        let destination = ctx.accounts.destination.key();
        let amount = ctx.accounts.withdraw_buffer.amount;

        ctx.accounts.withdraw_buffer.verified_destination = destination;
        ctx.accounts.withdraw_buffer.verified_amount = amount;

        // Transfer SOL from shared vault to destination
        let config_key = ctx.accounts.privacy_config.key();
        let fee_vault_bump = ctx.accounts.privacy_config.fee_vault_bump;
        let fee_vault_seeds: &[&[u8]] = &[
            SHARED_FEE_VAULT_SEED,
            config_key.as_ref(),
            &[fee_vault_bump],
        ];
        let signer_seeds: &[&[&[u8]]] = &[fee_vault_seeds];

        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.shared_fee_vault.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
        )?;

        emit!(crate::state::WithdrawProcessed {
            amount,
            destination,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!(
            "Withdraw fee callback: {} lamports sent to {}",
            amount,
            destination
        );
        Ok(())
    }

    // =========================================================================
    // ACCOUNT STRUCTS (must be inside arcium_program module)
    // =========================================================================


    /// Initialize store_claim computation definition accounts
    #[init_computation_definition_accounts("store_claim", payer)]
    #[derive(Accounts)]
    pub struct InitStoreClaimCompDef<'info> {
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

    /// Initialize verify_and_claim computation definition accounts
    #[init_computation_definition_accounts("verify_and_claim", payer)]
    #[derive(Accounts)]
    pub struct InitVerifyAndClaimCompDef<'info> {
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

    // Computation definition offsets are defined in their respective instruction files
    // They are generated by the comp_def_offset macro from arcium_anchor

    /// Callback accounts for store_claim
    /// IMPORTANT: Account order must match Arcium's expected callback format
    #[callback_accounts("store_claim")]
    #[derive(Accounts)]
    pub struct StoreClaimCallback<'info> {
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
    }

    /// Callback accounts for verify_and_claim
    /// IMPORTANT: Account order must match Arcium's expected callback format
    #[callback_accounts("verify_and_claim")]
    #[derive(Accounts)]
    pub struct VerifyAndClaimCallback<'info> {
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
        pub privacy_config: Account<'info, crate::state::PrivacyConfig>,

        /// Privacy authority PDA
        /// CHECK: PDA verified by seeds
        pub privacy_authority: UncheckedAccount<'info>,

        /// Token mint
        pub mint: InterfaceAccount<'info, Mint>,

        /// Shared token vault
        #[account(mut)]
        pub shared_token_vault: InterfaceAccount<'info, TokenAccount>,

        /// Destination token account (MPC decrypted destination)
        #[account(mut)]
        pub destination_token_account: InterfaceAccount<'info, TokenAccount>,

        pub token_program: Interface<'info, TokenInterface>,

        /// The claim being processed (to get amount and mark as claimed)
        #[account(mut)]
        pub claim: Account<'info, crate::state::Claim>,
    }

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

        #[account(mut)]
        pub mine_block_buffer: Box<Account<'info, crate::state::MineBlockBuffer>>,

        /// Shared fee vault (SOL source)
        /// CHECK: PDA verified by seeds
        #[account(mut)]
        pub shared_fee_vault: UncheckedAccount<'info>,

        /// PoW protocol fee vault (destination for protocol fee)
        /// CHECK: PDA from pow-protocol
        #[account(mut)]
        pub pow_fee_vault: UncheckedAccount<'info>,

        pub system_program: Program<'info, System>,
    }

    /// Callback accounts for withdraw_fee
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

        pub system_program: Program<'info, System>,
    }
}
