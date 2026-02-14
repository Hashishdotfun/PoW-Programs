use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::state::*;

pub fn handler(ctx: Context<Initialize>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;

    let config = &mut ctx.accounts.privacy_config;
    config.authority = ctx.accounts.authority.key();
    config.mint = ctx.accounts.mint.key();
    config.next_claim_id = 0;
    config.total_claims = 0;
    config.total_claims_processed = 0;
    config.total_tokens_distributed = 0;
    config.total_blocks = 0;
    config.is_active = true;
    config.created_at = now;
    config.bump = ctx.bumps.privacy_config;
    config.authority_bump = ctx.bumps.privacy_authority;
    config.token_vault_bump = ctx.bumps.shared_token_vault;
    config.fee_vault_bump = ctx.bumps.shared_fee_vault;

    // Initialize encrypted state placeholder
    let encrypted_state = &mut ctx.accounts.encrypted_state;
    encrypted_state.config = config.key();
    encrypted_state.mxe_id = [0u8; 32]; // Will be set when Arcium is integrated
    encrypted_state.balance_root = [0u8; 32];
    encrypted_state.entry_count = 0;
    encrypted_state.last_update = now;
    encrypted_state.bump = ctx.bumps.encrypted_state;

    emit!(PrivacyProtocolInitialized {
        config: config.key(),
        authority: config.authority,
        mint: config.mint,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Token mint (HASH token)
    pub mint: InterfaceAccount<'info, Mint>,

    /// Privacy protocol configuration
    #[account(
        init,
        payer = authority,
        space = PrivacyConfig::LEN,
        seeds = [PRIVACY_CONFIG_SEED],
        bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Privacy authority PDA (signs CPIs to pow-protocol)
    /// CHECK: PDA verified by seeds
    #[account(
        seeds = [PRIVACY_AUTHORITY_SEED, privacy_config.key().as_ref()],
        bump,
    )]
    pub privacy_authority: UncheckedAccount<'info>,

    /// Shared token vault (holds all mined tokens)
    #[account(
        init,
        payer = authority,
        seeds = [SHARED_TOKEN_VAULT_SEED, privacy_config.key().as_ref(), mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = privacy_authority,
    )]
    pub shared_token_vault: InterfaceAccount<'info, TokenAccount>,

    /// Shared fee vault (holds SOL for protocol fees)
    /// CHECK: PDA verified by seeds
    #[account(
        mut,
        seeds = [SHARED_FEE_VAULT_SEED, privacy_config.key().as_ref()],
        bump,
    )]
    pub shared_fee_vault: UncheckedAccount<'info>,

    /// Encrypted state (Arcium placeholder)
    #[account(
        init,
        payer = authority,
        space = EncryptedState::LEN,
        seeds = [ENCRYPTED_STATE_SEED, privacy_config.key().as_ref()],
        bump,
    )]
    pub encrypted_state: Account<'info, EncryptedState>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
