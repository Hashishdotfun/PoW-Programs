use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;

/// Create a withdrawal token buffer with encrypted amount, destination and current token state
/// This is step 1 of the HASHISH token withdrawal process
///
/// Flow:
/// 1. Miner creates WithdrawTokenBuffer with encrypted data
/// 2. Miner calls withdraw_token_private to trigger MPC verification
/// 3. MPC verifies balance, deducts amount, and returns destination
/// 4. Callback transfers HASHISH tokens to the verified destination (minus 0.5% fee)
pub fn handler(
    ctx: Context<CreateWithdrawTokenBuffer>,
    encrypted_amount: [u8; 32],
    encrypted_destination: [[u8; 32]; 4],
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

    let buffer = &mut ctx.accounts.withdraw_token_buffer;
    let clock = Clock::get()?;

    buffer.owner = ctx.accounts.creator.key();
    buffer.amount = amount;
    buffer.encrypted_amount = encrypted_amount;
    buffer.encrypted_destination = encrypted_destination;
    buffer.encrypted_current_token_state = encrypted_current_token_state;
    buffer.client_pubkey = client_pubkey;
    buffer.encryption_nonce = encryption_nonce;
    buffer.is_used = false;
    buffer.is_approved = false;
    buffer.is_executed = false;
    buffer.verified_destination = Pubkey::default();
    buffer.verified_amount = 0;
    buffer.created_at = clock.unix_timestamp;
    buffer.bump = ctx.bumps.withdraw_token_buffer;

    emit!(WithdrawTokenBufferCreated {
        buffer: buffer.key(),
        owner: ctx.accounts.creator.key(),
        amount,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(
    encrypted_amount: [u8; 32],
    encrypted_destination: [[u8; 32]; 4],
    encrypted_current_token_state: [[u8; 32]; 3],
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    amount: u64,
)]
pub struct CreateWithdrawTokenBuffer<'info> {
    /// Creator can be any wallet (privacy: allows using throwaway wallet)
    #[account(mut)]
    pub creator: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Withdraw token buffer PDA
    #[account(
        init,
        payer = creator,
        space = WithdrawTokenBuffer::LEN,
        seeds = [
            WITHDRAW_TOKEN_BUFFER_SEED,
            creator.key().as_ref(),
            &encrypted_amount[..8],
        ],
        bump,
    )]
    pub withdraw_token_buffer: Account<'info, WithdrawTokenBuffer>,

    pub system_program: Program<'info, System>,
}
