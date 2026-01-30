use anchor_lang::prelude::*;

use crate::constants::*;
use crate::state::*;
use crate::errors::ErrorCode;

/// Initialize a claim buffer with metadata (without encrypted bytes)
/// This is the first transaction in a multi-transaction flow
/// Subsequent append_claim_buffer calls will add the encrypted bytes
pub fn handler_init(
    ctx: Context<InitClaimBuffer>,
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    secret_hash: [u8; 32],
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;

    let buffer = &mut ctx.accounts.claim_buffer;
    buffer.owner = ctx.accounts.payer.key();
    buffer.encrypted_claim_bytes = Vec::with_capacity(MAX_ENCRYPTED_DESTINATION_LEN);
    buffer.client_pubkey = client_pubkey;
    buffer.encryption_nonce = encryption_nonce;
    buffer.secret_hash = secret_hash;
    buffer.is_used = false;
    buffer.created_at = now;
    buffer.bump = ctx.bumps.claim_buffer;

    emit!(ClaimBufferCreated {
        buffer: buffer.key(),
        owner: buffer.owner,
        timestamp: now,
    });

    Ok(())
}

/// Append encrypted bytes to an existing claim buffer
/// Can be called multiple times to fill the buffer with 1088 bytes
pub fn handler_append(
    ctx: Context<AppendClaimBuffer>,
    data: Vec<u8>,
) -> Result<()> {
    let buffer = &mut ctx.accounts.claim_buffer;

    // Verify buffer isn't already used
    require!(!buffer.is_used, ErrorCode::ClaimBufferAlreadyUsed);

    // Verify we won't exceed max length
    let new_len = buffer.encrypted_claim_bytes.len() + data.len();
    require!(
        new_len <= MAX_ENCRYPTED_DESTINATION_LEN,
        ErrorCode::InvalidEncryptedData
    );

    // Append the data
    buffer.encrypted_claim_bytes.extend(data);

    msg!("Buffer now has {} bytes", buffer.encrypted_claim_bytes.len());

    Ok(())
}

#[derive(Accounts)]
#[instruction(
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    secret_hash: [u8; 32],
)]
pub struct InitClaimBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Privacy config (to verify protocol is active)
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
        constraint = privacy_config.is_active @ ErrorCode::ProtocolPaused,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Claim buffer PDA - unique per owner + secret_hash
    #[account(
        init,
        payer = payer,
        space = ClaimBuffer::LEN,
        seeds = [CLAIM_BUFFER_SEED, payer.key().as_ref(), &secret_hash],
        bump,
    )]
    pub claim_buffer: Account<'info, ClaimBuffer>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AppendClaimBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Claim buffer to append to
    #[account(
        mut,
        seeds = [CLAIM_BUFFER_SEED, payer.key().as_ref(), &claim_buffer.secret_hash],
        bump = claim_buffer.bump,
        constraint = claim_buffer.owner == payer.key() @ ErrorCode::Unauthorized,
        constraint = !claim_buffer.is_used @ ErrorCode::ClaimBufferAlreadyUsed,
    )]
    pub claim_buffer: Account<'info, ClaimBuffer>,
}
