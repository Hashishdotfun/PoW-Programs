use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::state::*;

pub fn handler(ctx: Context<Initialize>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;

    let config = &mut ctx.accounts.privacy_config;
    config.authority = ctx.accounts.authority.key();
    config.mint = ctx.accounts.mint.key();
    config.total_tokens_distributed = 0;
    config.total_blocks = 0;
    config.is_active = true;
    config.created_at = now;
    config.bump = ctx.bumps.privacy_config;
    config.authority_bump = ctx.bumps.privacy_authority;
    config.token_vault_bump = ctx.bumps.shared_token_vault;
    config.fee_vault_bump = ctx.bumps.shared_fee_vault;
    config.team_wallet = Pubkey::default();
    config.team_token_account = Pubkey::default();
    config.withdrawal_fee_bps = DEFAULT_WITHDRAWAL_FEE_BPS;

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

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
