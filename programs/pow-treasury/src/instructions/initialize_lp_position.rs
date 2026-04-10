// =============================================================================
// INSTRUCTION: INITIALIZE LP POSITION
// =============================================================================
// Crée la position LP permanente dans le pool Meteora DAMM v2.
// Authority only. Appelé une seule fois.
// DAMM v2 utilise un NFT mint pour représenter les positions.
// La position est ensuite réutilisée par execute_lp_cycle à chaque cycle.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TreasuryError;
use crate::state::TreasuryConfig;
use crate::meteora_cpi;

/// Initialise la position LP permanente du treasury.
///
/// Authority only. Crée une position DAMM v2 détenue par le treasury_config PDA.
/// La position est représentée par un NFT mint.
/// Les adresses position + position_nft_mint sont stockées dans treasury_config.
pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, InitializeLpPosition<'info>>,
) -> Result<()> {
    let config = &ctx.accounts.treasury_config;

    // Allow re-initialization if authority calls it (to replace a corrupted position)
    if config.lp_position != Pubkey::default() {
        msg!("Replacing existing LP position: {}", config.lp_position);
    }

    let config_bump = config.bump;
    let config_seeds: &[&[&[u8]]] = &[&[
        TREASURY_CONFIG_SEED,
        &[config_bump],
    ]];

    // CPI Meteora DAMM v2 create_position
    meteora_cpi::create_position(
        meteora_cpi::CreatePositionAccounts {
            owner: ctx.accounts.treasury_config.to_account_info(),
            position_nft_mint: ctx.accounts.position_nft_mint.to_account_info(),
            position_nft_account: ctx.accounts.position_nft_account.to_account_info(),
            pool: ctx.accounts.damm_pool.to_account_info(),
            position: ctx.accounts.position.to_account_info(),
            pool_authority: ctx.accounts.pool_authority.to_account_info(),
            payer: ctx.accounts.authority.to_account_info(),
            token_program: ctx.accounts.token_program.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            damm_program: ctx.accounts.damm_program.to_account_info(),
        },
        config_seeds,
    )?;

    // Save position + NFT mint addresses
    let config = &mut ctx.accounts.treasury_config;
    config.lp_position = ctx.accounts.position.key();
    config.position_nft_mint = ctx.accounts.position_nft_mint.key();
    config.total_lp_positions = 1;

    msg!("LP position initialized (DAMM v2):");
    msg!("  Position: {}", ctx.accounts.position.key());
    msg!("  NFT mint: {}", ctx.accounts.position_nft_mint.key());

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeLpPosition<'info> {
    /// Authority du treasury (seule peut créer la position)
    #[account(
        mut,
        constraint = authority.key() == treasury_config.authority @ TreasuryError::Unauthorized,
    )]
    pub authority: Signer<'info>,

    /// Treasury config
    #[account(
        mut,
        seeds = [TREASURY_CONFIG_SEED],
        bump = treasury_config.bump,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,

    /// Position NFT mint (new keypair, must sign)
    /// CHECK: Initialisé par CPI Meteora DAMM v2
    #[account(mut, signer)]
    pub position_nft_mint: AccountInfo<'info>,

    /// Position NFT token account (PDA: ["position_nft_account", position_nft_mint])
    /// CHECK: Initialisé par CPI Meteora DAMM v2
    #[account(mut)]
    pub position_nft_account: AccountInfo<'info>,

    /// Position PDA (seeds: ["position", position_nft_mint])
    /// CHECK: Initialisé par CPI Meteora DAMM v2
    #[account(mut)]
    pub position: AccountInfo<'info>,

    /// Pool Meteora DAMM v2
    /// CHECK: Validé par contrainte
    #[account(
        mut,
        constraint = damm_pool.key() == treasury_config.damm_pool @ TreasuryError::InvalidPool,
    )]
    pub damm_pool: AccountInfo<'info>,

    /// DAMM v2 pool authority (constant PDA)
    /// CHECK: Compte Meteora
    pub pool_authority: AccountInfo<'info>,

    /// Event authority (PDA de Meteora)
    /// CHECK: Compte Meteora
    pub event_authority: AccountInfo<'info>,

    /// Meteora DAMM v2 program
    /// CHECK: Programme Meteora
    pub damm_program: AccountInfo<'info>,

    /// CHECK: SPL Token program (for NFT mint)
    pub token_program: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}
