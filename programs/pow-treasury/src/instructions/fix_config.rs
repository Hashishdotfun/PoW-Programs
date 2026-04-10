// =============================================================================
// INSTRUCTION: FIX CONFIG (temporary migration)
// =============================================================================
// Corrige le bump et last_consumed_cycle après ajout du champ dans la struct.
// Authority only. À retirer après migration.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::state::TreasuryConfig;

pub fn handler(ctx: Context<FixConfig>) -> Result<()> {
    let config = &mut ctx.accounts.treasury_config;

    // Rewrite the bump from the actual PDA derivation
    let correct_bump = ctx.bumps.treasury_config;
    msg!("Fixing bump: {} -> {}", config.bump, correct_bump);
    config.bump = correct_bump;

    // Reset last_consumed_cycle to 0 (was reading garbage from old layout)
    msg!("Fixing last_consumed_cycle: {} -> 0", config.last_consumed_cycle);
    config.last_consumed_cycle = 0;

    msg!("Config fixed!");
    Ok(())
}

#[derive(Accounts)]
pub struct FixConfig<'info> {
    #[account(
        constraint = authority.key() == treasury_config.authority,
    )]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [TREASURY_CONFIG_SEED],
        bump,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,
}
