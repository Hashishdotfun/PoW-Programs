// =============================================================================
// INSTRUCTION: MIGRATE MEGA STATE → V3
// =============================================================================
// V3 ajoute deux challenges dédiés (`mega_challenge`, `super_mega_challenge`)
// au compte `MegaState`, soit 64 bytes en plus de la taille V2.
//
// Cette instruction est idempotente:
//   - Réalloue le compte si nécessaire (V2 → V3, +64 bytes)
//   - Initialise les deux challenges depuis `pow_config.current_challenge`
//     uniquement si ils sont encore à zéro (premier appel)
//   - Subsequent calls = no-op
//
// Doit être appelée par le `authority` du `pow_config` SEEKER, après le
// program upgrade qui ship V3.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{MegaState, PowConfig};

pub fn handler(ctx: Context<MigrateMegaStateV3>) -> Result<()> {
    let pow_config = &ctx.accounts.pow_config;
    require!(pow_config.is_initialized, PowError::NotInitialized);
    require!(pow_config.pool_id == POOL_SEEKER, PowError::MegaOnSeekerOnly);

    let mega_state = &mut ctx.accounts.mega_state;

    // Idempotent: skip if already populated.
    let zero_challenge = [0u8; 32];
    if mega_state.mega_challenge != zero_challenge {
        msg!("MegaState already migrated to V3 — no-op");
        return Ok(());
    }

    mega_state.mega_challenge = pow_config.current_challenge;
    mega_state.super_mega_challenge = pow_config.current_challenge;

    msg!("MegaState migrated to V3 — per-level challenges seeded from current_challenge");
    Ok(())
}

#[derive(Accounts)]
pub struct MigrateMegaStateV3<'info> {
    /// L'autorité du `pow_config` seeker — paie le surcoût de rent du realloc.
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Pool seeker (id = 1). Boxé pour éviter de saturer la stack frame.
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_SEEKER]],
        bump = pow_config.bump,
        constraint = pow_config.authority == authority.key() @ PowError::Unauthorized,
    )]
    pub pow_config: Box<Account<'info, PowConfig>>,

    /// Singleton MegaState — réalloué à `MegaState::LEN` (V3 size).
    #[account(
        mut,
        seeds = [MEGA_STATE_SEED],
        bump = mega_state.bump,
        realloc = MegaState::LEN,
        realloc::payer = authority,
        realloc::zero = false,
    )]
    pub mega_state: Box<Account<'info, MegaState>>,

    pub system_program: Program<'info, System>,
}
