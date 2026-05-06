// =============================================================================
// INSTRUCTION: FUND TREASURY
// =============================================================================
// Transfère le SOL des vaults de pow-protocol vers les vaults de pow-treasury
// via CPI vers pow-protocol::transfer_to_treasury

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::state::TreasuryConfig;

/// Alimente le treasury en SOL depuis les vaults de pow-protocol
///
/// Permissionless - n'importe qui peut appeler.
/// CPI vers pow-protocol::transfer_to_treasury pour récupérer le SOL
/// des buyback_vault et lp_vault.
pub fn handler(ctx: Context<FundTreasury>) -> Result<()> {
    let balance_before = ctx.accounts.treasury_sol_vault.lamports();

    // CPI vers pow-protocol::transfer_to_treasury
    let treasury_config_bump = ctx.accounts.treasury_config.bump;
    let signer_seeds: &[&[&[u8]]] = &[&[
        TREASURY_CONFIG_SEED,
        &[treasury_config_bump],
    ]];

    let cpi_accounts = pow_protocol::cpi::accounts::TransferToTreasury {
        payer: ctx.accounts.payer.to_account_info(),
        buyback_vault: ctx.accounts.buyback_vault.to_account_info(),
        lp_vault: ctx.accounts.lp_vault.to_account_info(),
        treasury_sol_vault: ctx.accounts.treasury_sol_vault.to_account_info(),
        system_program: ctx.accounts.system_program.to_account_info(),
    };

    let cpi_ctx = CpiContext::new_with_signer(
        ctx.accounts.pow_protocol_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );

    pow_protocol::cpi::transfer_to_treasury(cpi_ctx)?;

    let balance_after = ctx.accounts.treasury_sol_vault.lamports();
    let transferred = balance_after.saturating_sub(balance_before);

    msg!("Treasury funded: {} lamports received", transferred);

    Ok(())
}

#[derive(Accounts)]
pub struct FundTreasury<'info> {
    /// Cranker/payer
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Treasury config (pour le PDA signer)
    #[account(
        seeds = [TREASURY_CONFIG_SEED],
        bump,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,

    /// Treasury SOL vault (destination)
    /// CHECK: PDA du treasury
    #[account(
        mut,
        seeds = [TREASURY_SOL_VAULT_SEED],
        bump,
    )]
    pub treasury_sol_vault: AccountInfo<'info>,

    // === Comptes pow-protocol passés pour le CPI ===

    /// Buyback vault de pow-protocol (source)
    /// CHECK: PDA de pow-protocol, vérifié par le CPI
    #[account(mut)]
    pub buyback_vault: AccountInfo<'info>,

    /// LP vault de pow-protocol (source)
    /// CHECK: PDA de pow-protocol, vérifié par le CPI
    #[account(mut)]
    pub lp_vault: AccountInfo<'info>,

    /// Programme pow-protocol
    /// CHECK: Validé par la contrainte sur treasury_config
    #[account(
        constraint = pow_protocol_program.key() == treasury_config.pow_protocol
    )]
    pub pow_protocol_program: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}
