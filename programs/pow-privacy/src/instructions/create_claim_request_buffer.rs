use anchor_lang::prelude::*;

use crate::constants::*;
use crate::state::*;

/// Initialize a claim request buffer with all data
/// Now fits in a single transaction since we use [u64; 4] for secret (128 bytes)
pub fn handler_init(
    ctx: Context<InitClaimRequestBuffer>,
    claim_id: u64,
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    secret: [u8; 32],
    encrypted_claim_id: [u8; 32],       // 1 ciphertext for u64
    encrypted_secret: [[u8; 32]; 4],    // 4 ciphertexts for [u64; 4]
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let buffer = &mut ctx.accounts.claim_request_buffer;

    buffer.owner = ctx.accounts.payer.key();
    buffer.claim_id = claim_id;
    buffer.encrypted_claim_id = encrypted_claim_id;
    buffer.encrypted_secret = encrypted_secret;
    buffer.client_pubkey = client_pubkey;
    buffer.encryption_nonce = encryption_nonce;
    buffer.secret = secret;
    buffer.is_used = false;
    buffer.created_at = now;
    buffer.bump = ctx.bumps.claim_request_buffer;

    emit!(ClaimRequestBufferCreated {
        buffer: ctx.accounts.claim_request_buffer.key(),
        owner: ctx.accounts.payer.key(),
        claim_id,
        timestamp: now,
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(claim_id: u64, client_pubkey: [u8; 32], encryption_nonce: u128, secret: [u8; 32])]
pub struct InitClaimRequestBuffer<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Claim request buffer PDA (keyed by owner + claim_id)
    #[account(
        init,
        payer = payer,
        space = ClaimRequestBuffer::LEN,
        seeds = [CLAIM_REQUEST_BUFFER_SEED, payer.key().as_ref(), &claim_id.to_le_bytes()],
        bump,
    )]
    pub claim_request_buffer: Account<'info, ClaimRequestBuffer>,

    pub system_program: Program<'info, System>,
}
