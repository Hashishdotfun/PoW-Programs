// =============================================================================
// INSTRUCTION: DISABLE TRANSFER FEE CONFIG AUTHORITY
// =============================================================================
//
// One-shot irreversible operation. Callable only by the protocol authority.
//
// Revokes the SPL Token-2022 `TransferFeeConfig` authority on the HASHISH mint
// by CPI-signing with the `fee_authority` PDA (seeds = ["fee_authority", mint]).
//
// After this call, the transfer fee rate and maximum are permanently locked.
// The withdraw-withheld authority is deliberately left intact so that
// `collect_transfer_fees` can keep harvesting the 0.01% tax.
//
// The mint authority is NOT touched by this instruction — it remains the
// `MintAuthority` PDA so that `submit_proof` can keep minting block rewards.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{
    set_authority, spl_token_2022::instruction::AuthorityType, SetAuthority,
};
use anchor_spl::token_interface::{Mint, TokenInterface};

use super::collect_transfer_fees::FEE_AUTHORITY_SEED;
use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;

pub fn handler(ctx: Context<DisableTransferFeeConfigAuthority>) -> Result<()> {
    let mint_key = ctx.accounts.mint.key();

    let fee_auth_bump = ctx.bumps.fee_authority;
    let mint_key_bytes = mint_key.as_ref();
    let signer_seeds: &[&[&[u8]]] = &[&[
        FEE_AUTHORITY_SEED,
        mint_key_bytes,
        &[fee_auth_bump],
    ]];

    set_authority(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            SetAuthority {
                account_or_mint: ctx.accounts.mint.to_account_info(),
                current_authority: ctx.accounts.fee_authority.to_account_info(),
            },
            signer_seeds,
        ),
        AuthorityType::TransferFeeConfig,
        None,
    )?;

    msg!(
        "Transfer fee config authority permanently disabled on mint {}",
        mint_key
    );
    Ok(())
}

// =============================================================================
// ACCOUNTS
// =============================================================================

#[derive(Accounts)]
pub struct DisableTransferFeeConfigAuthority<'info> {
    /// Protocol authority — must match `pow_config_normal.authority`.
    pub authority: Signer<'info>,

    /// Pool 0 config used for the authority check.
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config_normal.bump,
        constraint = pow_config_normal.authority == authority.key() @ PowError::Unauthorized,
        has_one = mint @ PowError::InvalidMint,
    )]
    pub pow_config_normal: Box<Account<'info, PowConfig>>,

    /// The HASHISH mint (SPL Token-2022).
    #[account(mut, mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Fee authority PDA — signs the SetAuthority CPI.
    /// Seeds: ["fee_authority", mint]
    /// CHECK: PDA used only as a CPI signer.
    #[account(
        seeds = [FEE_AUTHORITY_SEED, mint.key().as_ref()],
        bump,
    )]
    pub fee_authority: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}
