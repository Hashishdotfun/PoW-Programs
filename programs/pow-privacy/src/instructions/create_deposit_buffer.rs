use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;

/// Create a deposit buffer with encrypted miner identification
/// This is step 1 of the deposit process
///
/// Flow:
/// 1. Miner creates DepositBuffer with encrypted miner_id_hash
/// 2. Miner calls deposit_private to transfer SOL and trigger MPC
/// 3. MPC verifies signature and updates encrypted balance
pub fn handler(
    ctx: Context<CreateDepositBuffer>,
    encrypted_miner_id_hash: [[u8; 32]; 4],
    encrypted_amount: [u8; 32],
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

    let buffer = &mut ctx.accounts.deposit_buffer;
    let clock = Clock::get()?;

    buffer.owner = ctx.accounts.depositor.key();
    buffer.amount = amount;
    buffer.encrypted_miner_id_hash = encrypted_miner_id_hash;
    buffer.encrypted_amount = encrypted_amount;
    buffer.encrypted_signature = encrypted_signature;
    buffer.client_pubkey = client_pubkey;
    buffer.encryption_nonce = encryption_nonce;
    buffer.is_used = false;
    buffer.created_at = clock.unix_timestamp;
    buffer.bump = ctx.bumps.deposit_buffer;

    emit!(DepositBufferCreated {
        buffer: buffer.key(),
        owner: ctx.accounts.depositor.key(),
        amount,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[derive(Accounts)]
#[instruction(
    encrypted_miner_id_hash: [[u8; 32]; 4],
    encrypted_amount: [u8; 32],
    encrypted_signature: [[u8; 32]; 8],
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    amount: u64,
)]
pub struct CreateDepositBuffer<'info> {
    /// Depositor who will fund the deposit
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Deposit buffer PDA
    /// Derived from owner + encrypted_miner_id_hash to ensure uniqueness
    #[account(
        init,
        payer = depositor,
        space = DepositBuffer::LEN,
        seeds = [
            DEPOSIT_BUFFER_SEED,
            depositor.key().as_ref(),
            &encrypted_miner_id_hash[0][..8],  // Use first 8 bytes for uniqueness
        ],
        bump,
    )]
    pub deposit_buffer: Account<'info, DepositBuffer>,

    pub system_program: Program<'info, System>,
}
