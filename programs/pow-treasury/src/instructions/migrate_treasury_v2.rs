// =============================================================================
// INSTRUCTION: MIGRATE TREASURY → V2 LAYOUT
// =============================================================================
// Quand le contrat treasury a été upgradé du layout V1 (avec
// `last_consumed_cycle: u64` à l'offset 221, bump à 229, lp_position à 230,
// position_nft_mint à 262) vers V2 (qui split en `last_consumed_buyback_cycle`
// + `last_consumed_lp_cycle`, décale tout de 8 bytes), le compte on-chain
// existant est resté en layout V1 — du coup Anchor lit n'importe quoi pour
// `bump`, `lp_position`, `position_nft_mint`.
//
// Cette instruction ré-écrit les bytes au bon endroit:
//   - last_consumed_buyback_cycle (221..229) → preserved (déjà correct par hasard)
//   - last_consumed_lp_cycle (229..237)      ← copie de last_consumed_buyback_cycle
//   - bump (237)                              ← canonical bump
//   - lp_position (238..270)                  ← old bytes 230..262
//   - position_nft_mint (270..302)            ← old bytes 262..294
//
// Idempotente: skip si le bump byte à l'offset 237 est déjà canonical.
// Authority-only: vérifie le pubkey stocké à l'offset 8..40 manuellement
// (impossible d'utiliser has_one sur un UncheckedAccount).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TreasuryError;

const OFF_AUTHORITY: usize = 8;
const OFF_LAST_CONSUMED_BUYBACK: usize = 221;
const OFF_LAST_CONSUMED_LP: usize = 229;
const OFF_BUMP: usize = 237;
const OFF_LP_POSITION: usize = 238;
const OFF_POSITION_NFT: usize = 270;

const OLD_OFF_BUMP: usize = 229;
const OLD_OFF_LP_POSITION: usize = 230;
const OLD_OFF_POSITION_NFT: usize = 262;

pub fn handler(ctx: Context<MigrateTreasuryV2>) -> Result<()> {
    let config_ai = &ctx.accounts.treasury_config;
    let mut data = config_ai.try_borrow_mut_data()?;

    let canonical_bump = ctx.bumps.treasury_config;

    // Idempotent: skip si déjà migré.
    if data[OFF_BUMP] == canonical_bump {
        msg!("Treasury already migrated to V2 layout — no-op");
        return Ok(());
    }

    // Authority check — read pubkey at offset 8..40.
    let stored_authority = Pubkey::try_from(&data[OFF_AUTHORITY..OFF_AUTHORITY + 32])
        .map_err(|_| TreasuryError::Unauthorized)?;
    require!(
        stored_authority == ctx.accounts.authority.key(),
        TreasuryError::Unauthorized
    );

    // Sanity: l'ancien bump (offset 229) DOIT être canonical, sinon le compte
    // n'est pas dans la layout V1 attendue.
    require!(
        data[OLD_OFF_BUMP] == canonical_bump,
        TreasuryError::Unauthorized
    );

    // Save old lp_position + position_nft_mint avant de les écraser.
    let mut old_lp_pos = [0u8; 32];
    old_lp_pos.copy_from_slice(&data[OLD_OFF_LP_POSITION..OLD_OFF_LP_POSITION + 32]);
    let mut old_pos_nft = [0u8; 32];
    old_pos_nft.copy_from_slice(&data[OLD_OFF_POSITION_NFT..OLD_OFF_POSITION_NFT + 32]);

    // Old last_consumed_cycle at offset 221..229 — preserved as new
    // last_consumed_buyback_cycle (same offset, same value).
    let last_consumed_buyback =
        u64::from_le_bytes(data[OFF_LAST_CONSUMED_BUYBACK..OFF_LAST_CONSUMED_BUYBACK + 8]
            .try_into()
            .unwrap());

    // Write new fields. Order matters: write LP fields BEFORE shifting the
    // pubkeys, since we read from offsets that overlap the write targets.
    // (We saved them above so the source data is buffered.)

    // last_consumed_lp_cycle (229..237) ← copie de buyback
    data[OFF_LAST_CONSUMED_LP..OFF_LAST_CONSUMED_LP + 8]
        .copy_from_slice(&last_consumed_buyback.to_le_bytes());
    // bump (237) ← canonical
    data[OFF_BUMP] = canonical_bump;
    // lp_position (238..270)
    data[OFF_LP_POSITION..OFF_LP_POSITION + 32].copy_from_slice(&old_lp_pos);
    // position_nft_mint (270..302)
    data[OFF_POSITION_NFT..OFF_POSITION_NFT + 32].copy_from_slice(&old_pos_nft);

    msg!(
        "Treasury migrated to V2 layout. last_consumed_buyback={} last_consumed_lp={} bump={}",
        last_consumed_buyback,
        last_consumed_buyback,
        canonical_bump,
    );
    Ok(())
}

#[derive(Accounts)]
pub struct MigrateTreasuryV2<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    /// CHECK: layout transition. Anchor cannot deserialize as TreasuryConfig
    /// because the stored bump byte (V1 layout) reads as garbage in V2 layout.
    /// Authority verified manually inside the handler against the stored
    /// pubkey at offset 8..40.
    #[account(
        mut,
        seeds = [TREASURY_CONFIG_SEED],
        bump,
    )]
    pub treasury_config: UncheckedAccount<'info>,
}
