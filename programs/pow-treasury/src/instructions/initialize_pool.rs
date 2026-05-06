// =============================================================================
// INSTRUCTION: INITIALIZE POOL
// =============================================================================
// Configure le pool Meteora DAMM v2 et crée le wSOL vault.
// Appelé après initialize() quand le pool Meteora est prêt.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::TreasuryError;
use crate::state::TreasuryConfig;

/// Configure le pool Meteora DAMM v2 pour le treasury
///
/// Crée le wSOL token account nécessaire pour les swaps Meteora.
/// Peut être appelé après initialize() pour mettre à jour le pool.
pub fn handler(
    ctx: Context<InitializePool>,
    damm_pool: Pubkey,
    max_slippage_bps: u16,
) -> Result<()> {
    require!(
        max_slippage_bps > 0 && max_slippage_bps <= ABSOLUTE_MAX_SLIPPAGE_BPS,
        TreasuryError::InvalidSlippage
    );

    let config = &mut ctx.accounts.treasury_config;

    require!(
        ctx.accounts.authority.key() == config.authority,
        TreasuryError::Unauthorized
    );

    config.damm_pool = damm_pool;
    config.max_slippage_bps = max_slippage_bps;

    msg!("Pool configured:");
    msg!("  DAMM v2 pool: {}", damm_pool);
    msg!("  Max slippage: {} bps", max_slippage_bps);
    msg!("  wSOL vault created");

    Ok(())
}

#[derive(Accounts)]
pub struct InitializePool<'info> {
    /// Authority du protocole
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Treasury config
    #[account(
        mut,
        seeds = [TREASURY_CONFIG_SEED],
        bump,
        has_one = authority @ TreasuryError::Unauthorized,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,

    /// wSOL vault pour les swaps Meteora (créé ici si première fois)
    #[account(
        init_if_needed,
        payer = authority,
        token::mint = wsol_mint,
        token::authority = treasury_config,
        token::token_program = token_program,
        seeds = [TREASURY_WSOL_VAULT_SEED],
        bump,
    )]
    pub wsol_vault: InterfaceAccount<'info, TokenAccount>,

    /// wSOL mint
    pub wsol_mint: InterfaceAccount<'info, Mint>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
