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
use anchor_lang::system_program::{self, Transfer};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{MegaState, PowConfig};

pub fn handler(ctx: Context<MigrateMegaStateV3>) -> Result<()> {
    let pow_config = &ctx.accounts.pow_config;
    require!(pow_config.is_initialized, PowError::NotInitialized);
    require!(pow_config.pool_id == POOL_SEEKER, PowError::MegaOnSeekerOnly);

    let mega_state_ai = &ctx.accounts.mega_state;
    let current_size = mega_state_ai.data_len();

    // V3 size already? → idempotent no-op.
    if current_size >= MegaState::LEN {
        msg!("MegaState already at V3 size ({} bytes) — no-op", current_size);
        return Ok(());
    }
    require!(
        current_size == MegaState::LEN_V2,
        PowError::InvalidAccountSize
    );

    // Top up rent so the larger account is rent-exempt at the new size.
    let target_size = MegaState::LEN;
    let needed_lamports = Rent::get()?.minimum_balance(target_size);
    let current_lamports = mega_state_ai.lamports();
    if needed_lamports > current_lamports {
        let delta = needed_lamports - current_lamports;
        system_program::transfer(
            CpiContext::new(
                ctx.accounts.system_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.authority.to_account_info(),
                    to: mega_state_ai.to_account_info(),
                },
            ),
            delta,
        )?;
    }

    // Grow the account in place. Anchor's `AccountInfo::realloc(_, false)` is
    // safe here: we only ever write the new tail bytes, never touching the
    // original 73 bytes of V2 state.
    mega_state_ai.realloc(target_size, false)?;

    // Append the two challenges at offsets [73..105] and [105..137]. Both
    // seeded from `pow_config.current_challenge` so the very next Mega/Super
    // proof has a valid challenge to mine against.
    let seed = pow_config.current_challenge;
    let mut data = mega_state_ai.try_borrow_mut_data()?;
    data[MegaState::LEN_V2..MegaState::LEN_V2 + 32].copy_from_slice(&seed);
    data[MegaState::LEN_V2 + 32..MegaState::LEN_V2 + 64].copy_from_slice(&seed);

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

    /// Singleton MegaState — toujours en layout V2 quand on entre ici. On
    /// utilise `UncheckedAccount` parce qu'Anchor refuserait de désérialiser
    /// un compte de 73 bytes comme `MegaState` (137 bytes V3). Le handler
    /// fait le realloc + write des challenges manuellement.
    /// CHECK: PDA dérivée par les seeds, taille vérifiée dans le handler.
    #[account(
        mut,
        seeds = [MEGA_STATE_SEED],
        bump,
    )]
    pub mega_state: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}
