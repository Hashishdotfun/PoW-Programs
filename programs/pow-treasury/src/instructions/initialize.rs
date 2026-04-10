// =============================================================================
// INSTRUCTION: INITIALIZE TREASURY
// =============================================================================

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::TreasuryError;
use crate::state::TreasuryConfig;

/// Initialise le programme treasury
///
/// Crée le TreasuryConfig PDA et les vaults nécessaires.
/// Doit être appelé une fois par l'authority du protocole.
pub fn handler(
    ctx: Context<InitializeTreasury>,
    damm_pool: Pubkey,
    max_slippage_bps: u16,
) -> Result<()> {
    require!(
        max_slippage_bps > 0 && max_slippage_bps <= ABSOLUTE_MAX_SLIPPAGE_BPS,
        TreasuryError::InvalidSlippage
    );

    let config = &mut ctx.accounts.treasury_config;
    config.authority = ctx.accounts.authority.key();
    config.pow_protocol = ctx.accounts.pow_protocol.key();
    config.mint = ctx.accounts.mint.key();
    config.damm_pool = damm_pool;

    // Cycle state
    config.current_phase = PHASE_BUYBACK;
    config.cycle_start_block = 0;
    config.tokens_for_lp = 0;
    config.last_cycle_ts = 0;
    config.total_cycles = 0;
    config.is_enabled = true;

    // LP tracking
    config.total_lp_positions = 0;
    config.max_slippage_bps = max_slippage_bps;
    config.cycle_attempts = 0;

    // Stats
    config.total_sol_swapped = 0;
    config.total_tokens_burned = 0;
    config.total_tokens_to_lp = 0;
    config.total_sol_to_lp = 0;
    config.total_cranker_rewards = 0;

    config.bump = ctx.bumps.treasury_config;

    msg!("Treasury initialized");
    msg!("  DAMM v2 pool: {}", damm_pool);
    msg!("  Max slippage: {} bps", max_slippage_bps);
    msg!("  Cycle length: {} blocks", BLOCKS_PER_CYCLE);

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeTreasury<'info> {
    /// L'authority du protocole (doit être la même que pow-protocol)
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Configuration du treasury (PDA, créée ici)
    #[account(
        init,
        payer = authority,
        space = TreasuryConfig::LEN,
        seeds = [TREASURY_CONFIG_SEED],
        bump,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,

    /// SOL vault du treasury
    /// CHECK: PDA, initialisé comme system account
    #[account(
        mut,
        seeds = [TREASURY_SOL_VAULT_SEED],
        bump,
    )]
    pub treasury_sol_vault: AccountInfo<'info>,

    /// Token vault du treasury (pour stocker les HASHISH achetés)
    #[account(
        init,
        payer = authority,
        token::mint = mint,
        token::authority = treasury_config,
        token::token_program = token_program,
        seeds = [TREASURY_TOKEN_VAULT_SEED],
        bump,
    )]
    pub treasury_token_vault: InterfaceAccount<'info, TokenAccount>,

    /// Le mint HASHISH (SPL2022)
    pub mint: InterfaceAccount<'info, Mint>,

    /// Programme pow-protocol (pour validation)
    /// CHECK: On vérifie que c'est bien un programme exécutable
    #[account(executable)]
    pub pow_protocol: AccountInfo<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}
