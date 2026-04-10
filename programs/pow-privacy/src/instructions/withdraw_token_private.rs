use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;
use crate::{ID, ID_CONST, ArciumSignerAccount};

// Computation definition offset for withdraw_token
const COMP_DEF_OFFSET_WITHDRAW_TOKEN: u32 = comp_def_offset("withdraw_token");

/// Build the ArgBuilder for withdraw_token MPC computation
/// Circuit signature: withdraw_token(amount, destination, current_token_state) -> WithdrawTokenResult
/// Input 1: Encrypted amount (1 ciphertext for Enc<Shared, u64>)
/// Input 2: Encrypted destination (4 ciphertexts for [u64; 4])
/// Input 3: Encrypted current_token_state (3 ciphertexts for MinerStateToken: token_balance, nonce, reserved)
#[inline(never)]
fn build_withdraw_token_args(
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    encrypted_amount: [u8; 32],
    encrypted_destination: [[u8; 32]; 4],
    encrypted_current_token_state: [[u8; 32]; 3],
) -> ArgumentList {
    ArgBuilder::new()
        // Input 1: encrypted amount (1 x u64)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_amount)
        // Input 2: encrypted destination (4 x u64)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_destination[0])
        .encrypted_u64(encrypted_destination[1])
        .encrypted_u64(encrypted_destination[2])
        .encrypted_u64(encrypted_destination[3])
        // Input 3: encrypted current_token_state (3 x u64: token_balance, nonce, reserved)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_current_token_state[0])
        .encrypted_u64(encrypted_current_token_state[1])
        .encrypted_u64(encrypted_current_token_state[2])
        .build()
}

/// Execute token withdrawal with MPC balance verification
/// This is step 2 of the HASHISH token withdrawal process
///
/// Flow:
/// 1. Verify withdraw token buffer exists and is unused
/// 2. Queue Arcium MPC computation to verify balance and deduct amount
/// 3. MPC callback will transfer HASHISH tokens if verification passes (minus 0.5% fee)
pub fn handler(ctx: Context<WithdrawTokenPrivate>, computation_offset: u64) -> Result<()> {
    let config = &ctx.accounts.privacy_config;
    let buffer = &ctx.accounts.withdraw_token_buffer;
    let clock = Clock::get()?;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Verify buffer is not already used
    require!(!buffer.is_used, ErrorCode::TokenBufferAlreadyUsed);

    // Build MPC arguments from the withdraw token buffer
    let args = build_withdraw_token_args(
        buffer.client_pubkey,
        buffer.encryption_nonce,
        buffer.encrypted_amount,
        buffer.encrypted_destination,
        buffer.encrypted_current_token_state,
    );

    // Set sign PDA bump
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

    // Import the callback from lib.rs
    use crate::pow_privacy::WithdrawTokenCallback;

    // Custom accounts must match WithdrawTokenCallback struct order exactly:
    // 1. privacy_config (mut)
    // 2. withdraw_token_buffer (mut)
    // Transfers are done in a separate execute_withdraw_token instruction
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![WithdrawTokenCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.privacy_config.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.withdraw_token_buffer.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,  // num_callback_txs
        0,  // cu_price_micro
    )?;

    emit!(MpcComputationQueued {
        computation_type: "withdraw_token".to_string(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[queue_computation_accounts("withdraw_token", caller)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct WithdrawTokenPrivate<'info> {
    /// Anyone can trigger the withdrawal (relayer or the miner themself)
    #[account(mut)]
    pub caller: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        mut,
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Box<Account<'info, PrivacyConfig>>,

    /// Withdraw token buffer with encrypted data
    #[account(
        mut,
        constraint = !withdraw_token_buffer.is_used @ ErrorCode::TokenBufferAlreadyUsed,
    )]
    pub withdraw_token_buffer: Box<Account<'info, WithdrawTokenBuffer>>,

    pub system_program: Program<'info, System>,

    // === Arcium MPC accounts ===

    /// Arcium sign PDA account
    #[account(
        init_if_needed,
        space = 9,
        payer = caller,
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

    /// Computation definition account for withdraw_token
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_WITHDRAW_TOKEN))]
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
