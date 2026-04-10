use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;
use crate::{ID, ID_CONST, ArciumSignerAccount};

// Computation definition offset for deposit_token
const COMP_DEF_OFFSET_DEPOSIT_TOKEN: u32 = comp_def_offset("deposit_token");

/// Build the ArgBuilder for deposit_token MPC computation
/// Circuit signature: deposit_token(amount, current_token_state) -> DepositTokenResult
/// Input 1: Encrypted amount (1 ciphertext for Enc<Shared, u64>)
/// Input 2: Encrypted current_token_state (3 ciphertexts for MinerStateToken: token_balance, nonce, reserved)
#[inline(never)]
fn build_deposit_token_args(
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    encrypted_amount: [u8; 32],
    encrypted_current_token_state: [[u8; 32]; 3],
) -> ArgumentList {
    ArgBuilder::new()
        // Input 1: encrypted amount (1 x u64)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_amount)
        // Input 2: encrypted current_token_state (3 x u64: token_balance, nonce, reserved)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_current_token_state[0])
        .encrypted_u64(encrypted_current_token_state[1])
        .encrypted_u64(encrypted_current_token_state[2])
        .build()
}

/// Execute token deposit with MPC balance update
/// This is step 2 of the HASHISH token deposit process
///
/// Flow:
/// 1. Verify deposit token buffer exists and is unused
/// 2. Queue Arcium MPC computation to update encrypted token balance
/// 3. MPC callback marks buffer as used
///
/// Note: No token transfer happens here — tokens are already in sharedTokenVault
/// (deposited via mining or manual SPL transfer)
pub fn handler(ctx: Context<DepositTokenPrivate>, computation_offset: u64) -> Result<()> {
    let config = &ctx.accounts.privacy_config;
    let buffer = &ctx.accounts.deposit_token_buffer;
    let clock = Clock::get()?;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Verify buffer is not already used
    require!(!buffer.is_used, ErrorCode::TokenBufferAlreadyUsed);

    // Build MPC arguments from the deposit token buffer
    let args = build_deposit_token_args(
        buffer.client_pubkey,
        buffer.encryption_nonce,
        buffer.encrypted_amount,
        buffer.encrypted_current_token_state,
    );

    // Set sign PDA bump
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

    // Import the callback from lib.rs
    use crate::pow_privacy::DepositTokenCallback;

    // Custom accounts must match DepositTokenCallback struct order exactly:
    // 1. privacy_config (mut)
    // 2. deposit_token_buffer (mut)
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![DepositTokenCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.privacy_config.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.deposit_token_buffer.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,  // num_callback_txs
        0,  // cu_price_micro
    )?;

    emit!(DepositTokenProcessed {
        amount: buffer.amount,
        timestamp: clock.unix_timestamp,
    });

    emit!(MpcComputationQueued {
        computation_type: "deposit_token".to_string(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[queue_computation_accounts("deposit_token", depositor)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct DepositTokenPrivate<'info> {
    /// Depositor who created the buffer
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        mut,
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Box<Account<'info, PrivacyConfig>>,

    /// Deposit token buffer with encrypted data
    #[account(
        mut,
        has_one = owner @ ErrorCode::InvalidOwner,
        constraint = !deposit_token_buffer.is_used @ ErrorCode::TokenBufferAlreadyUsed,
    )]
    pub deposit_token_buffer: Box<Account<'info, DepositTokenBuffer>>,

    /// Owner must match depositor
    /// CHECK: Verified via has_one
    #[account(address = depositor.key())]
    pub owner: AccountInfo<'info>,

    pub system_program: Program<'info, System>,

    // === Arcium MPC accounts ===

    /// Arcium sign PDA account
    #[account(
        init_if_needed,
        space = 9,
        payer = depositor,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, ArciumSignerAccount>>,

    /// MXE Account
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    /// Mempool account
    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: mempool_account, checked by the arcium program
    pub mempool_account: UncheckedAccount<'info>,

    /// Executing pool
    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: executing_pool, checked by the arcium program
    pub executing_pool: UncheckedAccount<'info>,

    /// Computation account
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: computation_account, checked by the arcium program
    pub computation_account: UncheckedAccount<'info>,

    /// Computation definition account for deposit_token
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_DEPOSIT_TOKEN))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

    /// Cluster account
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,

    /// Arcium fee pool account
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,

    /// Arcium clock account
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,

    /// Arcium program
    pub arcium_program: Program<'info, Arcium>,
}
