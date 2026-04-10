// =============================================================================
// INSTRUCTION: INITIALIZE FEE VAULT
// =============================================================================
// Creates the fee_authority PDA and fee_token_vault PDA.
// Called once by authority after the mint's withdrawWithheldAuthority
// has been set to the fee_authority PDA.

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;
use super::collect_transfer_fees::{FEE_AUTHORITY_SEED, FEE_TOKEN_VAULT_SEED};

/// Initialize the fee token vault for collecting SPL2022 transfer fees.
///
/// Authority only. Called once after deployment.
/// Creates the fee_token_vault PDA (token account owned by itself).
pub fn handler(ctx: Context<InitializeFeeVault>) -> Result<()> {
    msg!("Fee vault initialized:");
    msg!("  fee_authority PDA: {}", ctx.accounts.fee_authority.key());
    msg!("  fee_token_vault: {}", ctx.accounts.fee_token_vault.key());
    msg!("  Set this as withdrawWithheldAuthority on the mint:");
    msg!("  spl-token authorize <mint> withheldWithdraw {} --program-id TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
        ctx.accounts.fee_authority.key());

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeFeeVault<'info> {
    /// Authority (pays for account creation)
    #[account(
        mut,
        constraint = authority.key() == pow_config.authority @ PowError::Unauthorized,
    )]
    pub authority: Signer<'info>,

    /// PoW Config (to verify authority)
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config.bump,
    )]
    pub pow_config: Box<Account<'info, PowConfig>>,

    /// Token mint
    #[account(
        constraint = mint.key() == pow_config.mint @ PowError::InvalidMint,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Fee authority PDA — will become the withdrawWithheldAuthority.
    /// CHECK: PDA verified by seeds. Not a token account, just a signing PDA.
    #[account(
        seeds = [FEE_AUTHORITY_SEED, mint.key().as_ref()],
        bump,
    )]
    pub fee_authority: AccountInfo<'info>,

    /// Fee token vault PDA — holds withdrawn fees before distribution.
    /// Self-authority so only the program can burn from it.
    #[account(
        init,
        payer = authority,
        seeds = [FEE_TOKEN_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = fee_token_vault,
        token::token_program = token_program,
    )]
    pub fee_token_vault: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
