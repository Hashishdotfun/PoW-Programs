use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;

/// Create a withdrawal buffer with encrypted miner identification and destination
/// This is step 1 of the withdrawal process
///
/// Flow:
/// 1. Miner creates WithdrawBuffer with encrypted miner_id_hash and destination
/// 2. Miner calls withdraw_private to trigger MPC verification
/// 3. MPC verifies balance, deducts amount, and returns destination
/// 4. Callback transfers SOL to the verified destination
pub fn handler(
    ctx: Context<CreateWithdrawBuffer>,
    encrypted_miner_id_hash: [[u8; 32]; 4],
    encrypted_amount: [u8; 32],
    encrypted_destination: [[u8; 32]; 4],
    encrypted_signature: [[u8; 32]; 8],
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    amount: u64,
) -> Result<()> {
    let config = &ctx.accounts.privacy_config;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Verify amount is reasonable
    require!(amount > 0, ErrorCode::InvalidAmount);

    let buffer = &mut ctx.accounts.withdraw_buffer;
    let clock = Clock::get()?;

    buffer.owner = ctx.accounts.creator.key();
    buffer.amount = amount;
    buffer.encrypted_miner_id_hash = encrypted_miner_id_hash;
    buffer.encrypted_amount = encrypted_amount;
    buffer.encrypted_destination = encrypted_destination;
    buffer.encrypted_signature = encrypted_signature;
    buffer.client_pubkey = client_pubkey;
    buffer.encryption_nonce = encryption_nonce;
    buffer.is_used = false;
    buffer.is_approved = false;
    buffer.verified_destination = Pubkey::default();
    buffer.verified_amount = 0;
    buffer.created_at = clock.unix_timestamp;
    buffer.bump = ctx.bumps.withdraw_buffer;

    emit!(WithdrawBufferCreated {
        buffer: buffer.key(),
        owner: ctx.accounts.creator.key(),
        amount,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(
    encrypted_miner_id_hash: [[u8; 32]; 4],
    encrypted_amount: [u8; 32],
    encrypted_destination: [[u8; 32]; 4],
    encrypted_signature: [[u8; 32]; 8],
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    amount: u64,
)]
pub struct CreateWithdrawBuffer<'info> {
    /// Creator can be any wallet (privacy: allows using throwaway wallet)
    #[account(mut)]
    pub creator: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Withdraw buffer PDA
    /// Derived from creator + encrypted_miner_id_hash for uniqueness
    #[account(
        init,
        payer = creator,
        space = WithdrawBuffer::LEN,
        seeds = [
            WITHDRAW_BUFFER_SEED,
            creator.key().as_ref(),
            &encrypted_miner_id_hash[0][..8],  // Use first 8 bytes for uniqueness
        ],
        bump,
    )]
    pub withdraw_buffer: Account<'info, WithdrawBuffer>,

    pub system_program: Program<'info, System>,
}
