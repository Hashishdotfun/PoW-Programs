// =============================================================================
// INSTRUCTION: LOCK LP POSITION (permanent)
// =============================================================================
// Locks all unlocked liquidity in the treasury's DAMM v2 position.
// This is irreversible — locked liquidity can never be withdrawn.
// Fees can still be claimed on locked positions.
//
// Can be called by authority at any time (e.g. after position creation
// or after add_liquidity cycles to lock newly added liquidity).

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::TreasuryError;
use crate::state::TreasuryConfig;
use crate::meteora_cpi;

/// Byte offset of `unlocked_liquidity` (u128) in the DAMM v2 Position account.
/// Layout: 8 disc + 32 pool + 32 nft_mint + 32 fee_a_ckpt + 32 fee_b_ckpt + 8 fee_a + 8 fee_b = 152
const POSITION_UNLOCKED_LIQUIDITY_OFFSET: usize = 152;

/// Lock all unlocked liquidity in the treasury LP position.
///
/// Permissionless — anyone can call this to lock liquidity.
/// The position is owned by treasury_config PDA so only it can withdraw
/// (and we never expose a withdraw instruction), but permanent locking
/// adds an on-chain guarantee visible to everyone.
pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, LockLpPosition<'info>>,
) -> Result<()> {
    let config = &ctx.accounts.treasury_config;

    // Position must be initialized
    require!(
        config.lp_position != Pubkey::default(),
        TreasuryError::PositionNotInitialized
    );
    require!(
        ctx.accounts.position.key() == config.lp_position,
        TreasuryError::InvalidPosition
    );

    // Read unlocked_liquidity from position account data
    let position_data = ctx.accounts.position.try_borrow_data()?;
    require!(
        position_data.len() >= POSITION_UNLOCKED_LIQUIDITY_OFFSET + 16,
        TreasuryError::InvalidPosition
    );
    let unlocked_liquidity = u128::from_le_bytes(
        position_data[POSITION_UNLOCKED_LIQUIDITY_OFFSET..POSITION_UNLOCKED_LIQUIDITY_OFFSET + 16]
            .try_into()
            .unwrap(),
    );
    drop(position_data);

    if unlocked_liquidity == 0 {
        msg!("No unlocked liquidity to lock");
        return Ok(());
    }

    let config_bump = config.bump;
    let config_seeds: &[&[&[u8]]] = &[&[
        TREASURY_CONFIG_SEED,
        &[config_bump],
    ]];

    meteora_cpi::permanent_lock_position(
        meteora_cpi::PermanentLockPositionAccounts {
            pool: ctx.accounts.damm_pool.to_account_info(),
            position: ctx.accounts.position.to_account_info(),
            position_nft_account: ctx.accounts.position_nft_account.to_account_info(),
            owner: ctx.accounts.treasury_config.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            damm_program: ctx.accounts.damm_program.to_account_info(),
        },
        unlocked_liquidity,
        config_seeds,
    )?;

    msg!("Permanently locked {} liquidity units", unlocked_liquidity);

    Ok(())
}

#[derive(Accounts)]
pub struct LockLpPosition<'info> {
    /// Anyone can call this (permissionless lock)
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Treasury config
    #[account(
        seeds = [TREASURY_CONFIG_SEED],
        bump = treasury_config.bump,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,

    /// Position LP (DAMM v2 position PDA)
    /// CHECK: Validated against treasury_config.lp_position in handler
    #[account(mut)]
    pub position: AccountInfo<'info>,

    /// Position NFT token account (proves position ownership)
    /// CHECK: Meteora account
    pub position_nft_account: AccountInfo<'info>,

    /// Pool Meteora DAMM v2
    /// CHECK: Validated by constraint
    #[account(
        constraint = damm_pool.key() == treasury_config.damm_pool @ TreasuryError::InvalidPool,
    )]
    pub damm_pool: AccountInfo<'info>,

    /// Event authority (PDA de Meteora)
    /// CHECK: Meteora account
    pub event_authority: AccountInfo<'info>,

    /// Meteora DAMM v2 program
    /// CHECK: Meteora program
    pub damm_program: AccountInfo<'info>,
}
