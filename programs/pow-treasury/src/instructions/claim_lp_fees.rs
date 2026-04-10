// =============================================================================
// INSTRUCTION: CLAIM LP FEES
// =============================================================================
// Claim les trading fees des positions LP Meteora via CPI claim_position_fee.
// Les fees arrivent en wSOL + HASHISH:
// - wSOL → reste dans wsol_vault (utilisable au prochain cycle)
// - HASHISH → reste dans treasury_token_vault

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::TreasuryError;
use crate::state::TreasuryConfig;
use crate::meteora_cpi;

/// Claim les trading fees des positions LP Meteora DAMM v2
///
/// Authority only (gestion manuelle).
/// CPI vers Meteora DAMM v2 claim_position_fee pour récupérer les fees:
/// - wSOL (fees de trading côté SOL) → wsol_vault
/// - HASHISH (fees de trading côté token) → treasury_token_vault
pub fn handler(ctx: Context<ClaimLpFees>) -> Result<()> {
    let config = &ctx.accounts.treasury_config;

    require!(
        ctx.accounts.authority.key() == config.authority,
        TreasuryError::Unauthorized
    );

    let config_bump = config.bump;
    let config_seeds: &[&[&[u8]]] = &[&[
        TREASURY_CONFIG_SEED,
        &[config_bump],
    ]];

    // Record balances before claim
    let wsol_before = ctx.accounts.wsol_vault.amount;
    let token_before = ctx.accounts.treasury_token_vault.amount;

    // Determine token ordering based on pool's token_a/token_b
    let wsol_mint_key = ctx.accounts.wsol_mint.key();
    let (token_a_account, token_b_account, token_a_program, token_b_program) =
        if ctx.accounts.token_a_mint.key() == wsol_mint_key {
            (
                ctx.accounts.wsol_vault.to_account_info(),
                ctx.accounts.treasury_token_vault.to_account_info(),
                ctx.accounts.token_program_standard.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            )
        } else {
            (
                ctx.accounts.treasury_token_vault.to_account_info(),
                ctx.accounts.wsol_vault.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.token_program_standard.to_account_info(),
            )
        };

    // =========================================================================
    // CPI METEORA DAMM v2 CLAIM POSITION FEE
    // =========================================================================

    meteora_cpi::claim_fee(
        meteora_cpi::ClaimFeeAccounts {
            pool_authority: ctx.accounts.pool_authority.to_account_info(),
            pool: ctx.accounts.damm_pool.to_account_info(),
            position: ctx.accounts.position.to_account_info(),
            token_a_account,
            token_b_account,
            token_a_vault: ctx.accounts.token_a_vault.to_account_info(),
            token_b_vault: ctx.accounts.token_b_vault.to_account_info(),
            token_a_mint: ctx.accounts.token_a_mint.to_account_info(),
            token_b_mint: ctx.accounts.token_b_mint.to_account_info(),
            position_nft_account: ctx.accounts.position_nft_account.to_account_info(),
            owner: ctx.accounts.treasury_config.to_account_info(),
            token_a_program,
            token_b_program,
            event_authority: ctx.accounts.event_authority.to_account_info(),
            damm_program: ctx.accounts.damm_program.to_account_info(),
        },
        config_seeds,
    )?;

    // Reload to get updated balances
    ctx.accounts.wsol_vault.reload()?;
    ctx.accounts.treasury_token_vault.reload()?;

    let wsol_fees = ctx.accounts.wsol_vault.amount.saturating_sub(wsol_before);
    let token_fees = ctx.accounts.treasury_token_vault.amount.saturating_sub(token_before);

    msg!("LP fees claimed:");
    msg!("  wSOL fees: {} lamports", wsol_fees);
    msg!("  HASHISH fees: {} tokens", token_fees);

    if wsol_fees > 0 {
        msg!("wSOL fees ({}) available in wsol_vault for next cycle", wsol_fees);
    }

    if token_fees > 0 {
        msg!("HASHISH fees ({}) kept in treasury_token_vault", token_fees);
    }

    Ok(())
}

#[derive(Accounts)]
pub struct ClaimLpFees<'info> {
    /// Authority du protocole
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Treasury config
    #[account(
        seeds = [TREASURY_CONFIG_SEED],
        bump = treasury_config.bump,
        has_one = authority @ TreasuryError::Unauthorized,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,

    /// wSOL vault (destination des fees wSOL)
    #[account(
        mut,
        token::authority = treasury_config,
        seeds = [TREASURY_WSOL_VAULT_SEED],
        bump,
    )]
    pub wsol_vault: InterfaceAccount<'info, TokenAccount>,

    /// Treasury token vault (destination des fees HASHISH)
    #[account(
        mut,
        token::authority = treasury_config,
        token::token_program = token_program,
        seeds = [TREASURY_TOKEN_VAULT_SEED],
        bump,
    )]
    pub treasury_token_vault: InterfaceAccount<'info, TokenAccount>,

    /// wSOL mint
    pub wsol_mint: InterfaceAccount<'info, Mint>,

    // =========================================================================
    // COMPTES METEORA DAMM v2
    // =========================================================================

    /// Pool Meteora DAMM v2
    /// CHECK: Validé par contrainte
    #[account(
        constraint = damm_pool.key() == treasury_config.damm_pool @ TreasuryError::InvalidPool,
    )]
    pub damm_pool: AccountInfo<'info>,

    /// DAMM v2 pool authority (constant PDA)
    /// CHECK: Compte Meteora
    pub pool_authority: AccountInfo<'info>,

    /// Position LP
    /// CHECK: Compte Meteora position
    #[account(mut)]
    pub position: AccountInfo<'info>,

    /// Position NFT token account
    /// CHECK: Compte Meteora
    pub position_nft_account: AccountInfo<'info>,

    /// Pool token A vault
    /// CHECK: Compte Meteora
    #[account(mut)]
    pub token_a_vault: AccountInfo<'info>,

    /// Pool token B vault
    /// CHECK: Compte Meteora
    #[account(mut)]
    pub token_b_vault: AccountInfo<'info>,

    /// Token A mint
    pub token_a_mint: InterfaceAccount<'info, Mint>,

    /// Token B mint
    pub token_b_mint: InterfaceAccount<'info, Mint>,

    /// Event authority (PDA de Meteora)
    /// CHECK: Compte Meteora
    pub event_authority: AccountInfo<'info>,

    /// Meteora DAMM v2 program
    /// CHECK: Programme Meteora
    pub damm_program: AccountInfo<'info>,

    /// Token program standard (SPL Token, pour wSOL)
    /// CHECK: SPL Token program
    pub token_program_standard: AccountInfo<'info>,

    /// Token program (SPL Token 2022, pour HASHISH)
    pub token_program: Interface<'info, TokenInterface>,

    pub system_program: Program<'info, System>,
}
