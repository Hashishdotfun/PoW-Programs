// =============================================================================
// INSTRUCTION: INITIALIZE MEGA
// =============================================================================
// Initialise le PDA MegaState pour la pool seeker.
// Doit être appelé une seule fois après initialize(POOL_SEEKER).
// Snapshot la diff seeker actuelle × FACTOR pour mega et super-mega.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{MegaState, PowConfig};

pub fn handler(ctx: Context<InitializeMega>) -> Result<()> {
    let pow_config = &ctx.accounts.pow_config;

    require!(pow_config.is_initialized, PowError::NotInitialized);
    require!(pow_config.pool_id == POOL_SEEKER, PowError::MegaOnSeekerOnly);

    let mega_state = &mut ctx.accounts.mega_state;
    require!(
        mega_state.mega_difficulty == 0,
        PowError::MegaAlreadyInitialized
    );

    let seeker_diff = pow_config.difficulty;

    let mega_diff = seeker_diff
        .checked_mul(MEGA_FACTOR)
        .ok_or(PowError::Overflow)?;
    let super_mega_diff = seeker_diff
        .checked_mul(SUPER_MEGA_FACTOR)
        .ok_or(PowError::Overflow)?;

    mega_state.mega_difficulty = mega_diff;
    mega_state.super_mega_difficulty = super_mega_diff;
    mega_state.mega_count = 0;
    mega_state.super_mega_count = 0;
    mega_state.last_mega_ts = 0;
    mega_state.last_super_mega_ts = 0;
    mega_state.bump = ctx.bumps.mega_state;
    // V3: each level gets its own challenge, seeded from the pool's current
    // challenge so the very first Mega/Super proof works without needing a
    // separate priming step.
    mega_state.mega_challenge = pow_config.current_challenge;
    mega_state.super_mega_challenge = pow_config.current_challenge;

    msg!("MegaState initialized");
    msg!("  Seeker difficulty: {}", seeker_diff);
    msg!("  Mega difficulty:       {} (×{})", mega_diff, MEGA_FACTOR);
    msg!("  Super-mega difficulty: {} (×{})", super_mega_diff, SUPER_MEGA_FACTOR);

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeMega<'info> {
    /// L'autorité du protocole
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Configuration de la pool seeker (pool_id == 1)
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_SEEKER]],
        bump = pow_config.bump,
        constraint = pow_config.authority == authority.key() @ PowError::Unauthorized,
    )]
    pub pow_config: Account<'info, PowConfig>,

    /// PDA singleton qui stocke les diffs figées
    #[account(
        init,
        payer = authority,
        space = MegaState::LEN,
        seeds = [MEGA_STATE_SEED],
        bump,
    )]
    pub mega_state: Account<'info, MegaState>,

    pub system_program: Program<'info, System>,
}
