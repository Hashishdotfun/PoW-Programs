use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;

/// Create a deposit token buffer with encrypted amount and current token state
/// This is step 1 of the HASHISH token deposit process
///
/// Flow:
/// 1. Miner creates DepositTokenBuffer with encrypted amount and current token state
/// 2. Miner calls deposit_token_private to trigger MPC
/// 3. MPC updates encrypted token balance and returns new state
pub fn handler(
    ctx: Context<CreateDepositTokenBuffer>,
    encrypted_amount: [u8; 32],
    encrypted_current_token_state: [[u8; 32]; 3],
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    amount: u64,
) -> Result<()> {
    let config = &ctx.accounts.privacy_config;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Verify amount is reasonable
    require!(amount > 0, ErrorCode::InvalidAmount);

    let buffer = &mut ctx.accounts.deposit_token_buffer;
    let clock = Clock::get()?;

    buffer.owner = ctx.accounts.depositor.key();
    buffer.amount = amount;
    buffer.encrypted_amount = encrypted_amount;
    buffer.encrypted_current_token_state = encrypted_current_token_state;
    buffer.client_pubkey = client_pubkey;
    buffer.encryption_nonce = encryption_nonce;
    buffer.is_used = false;
    buffer.created_at = clock.unix_timestamp;
    buffer.bump = ctx.bumps.deposit_token_buffer;

    emit!(DepositTokenBufferCreated {
        buffer: buffer.key(),
        owner: ctx.accounts.depositor.key(),
        amount,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(
    encrypted_amount: [u8; 32],
    encrypted_current_token_state: [[u8; 32]; 3],
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    amount: u64,
)]
pub struct CreateDepositTokenBuffer<'info> {
    /// Depositor who will fund the token deposit
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Deposit token buffer PDA
    #[account(
        init,
        payer = depositor,
        space = DepositTokenBuffer::LEN,
        seeds = [
            DEPOSIT_TOKEN_BUFFER_SEED,
            depositor.key().as_ref(),
            &encrypted_amount[..8],
        ],
        bump,
    )]
    pub deposit_token_buffer: Account<'info, DepositTokenBuffer>,

    pub system_program: Program<'info, System>,
}
