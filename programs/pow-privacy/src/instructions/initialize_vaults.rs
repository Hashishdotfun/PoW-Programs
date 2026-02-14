use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::state::*;

/// Initialize missing vault PDAs without re-creating privacy_config or encrypted_state.
///
/// Use this when privacy_config already exists on-chain but the token vault
/// (and/or encrypted_state) was never created — e.g. after a program redeploy
/// where init-privacy.ts detected the existing config and skipped initialization.
pub fn handler(ctx: Context<InitializeVaults>) -> Result<()> {
    let config = &mut ctx.accounts.privacy_config;

    // Store the vault bump in privacy_config
    config.token_vault_bump = ctx.bumps.shared_token_vault;
    config.fee_vault_bump = ctx.bumps.shared_fee_vault;

    msg!(
        "Vaults initialized: token_vault_bump={}, fee_vault_bump={}",
        config.token_vault_bump,
        config.fee_vault_bump,
    );

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeVaults<'info> {
    /// Authority (must match privacy_config.authority)
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Token mint (HASH token)
    pub mint: InterfaceAccount<'info, Mint>,

    /// Existing privacy config (must already be initialized)
    #[account(
        mut,
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
        has_one = authority,
        has_one = mint,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Privacy authority PDA (token::authority for the vault)
    /// CHECK: PDA verified by seeds
    #[account(
        seeds = [PRIVACY_AUTHORITY_SEED, privacy_config.key().as_ref()],
        bump,
    )]
    pub privacy_authority: UncheckedAccount<'info>,

    /// Shared token vault — the PDA token account that holds mined tokens.
    /// Created here if it doesn't exist yet.
    #[account(
        init,
        payer = authority,
        seeds = [SHARED_TOKEN_VAULT_SEED, privacy_config.key().as_ref(), mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = privacy_authority,
    )]
    pub shared_token_vault: InterfaceAccount<'info, TokenAccount>,

    /// Shared fee vault (SOL). Just a PDA — no init needed, but we derive the bump.
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
