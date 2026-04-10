// =============================================================================
// INSTRUCTION: DISTRIBUTE FEES
// =============================================================================
// Distribue les fees SOL collectées:
// - 5% team
// - 95% direct vers treasury_sol_vault (pour buyback + LP)

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;
use crate::instructions::initialize::TeamVault;

/// Distribue les fees SOL accumulées
///
/// Permissionless — n'importe qui peut appeler.
/// - 5% → team_vault
/// - 95% → treasury_sol_vault (pow-treasury gère buyback/burn/LP)
pub fn handler(ctx: Context<DistributeFees>) -> Result<()> {
    let fee_collector = &ctx.accounts.fee_collector;
    let fee_balance = fee_collector.lamports();

    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(0);

    let distributable = fee_balance
        .checked_sub(min_balance)
        .ok_or(PowError::EmptyFeeVault)?;

    if distributable == 0 {
        msg!("No fees to distribute");
        return Ok(());
    }

    let config = &mut ctx.accounts.pow_config;

    // 5% pour la team
    let team_amount = distributable
        .checked_mul(TEAM_FEE_PCT)
        .ok_or(PowError::Overflow)?
        .checked_div(100)
        .ok_or(PowError::DivisionByZero)?;

    // 95% direct vers treasury
    let treasury_amount = distributable
        .checked_sub(team_amount)
        .ok_or(PowError::Underflow)?;

    let fee_vault_bump = ctx.bumps.fee_collector;
    let fee_vault_seeds: &[&[&[u8]]] = &[&[
        FEE_VAULT_SEED,
        &[fee_vault_bump],
    ]];

    // ==========================================================================
    // TEAM (5%)
    // ==========================================================================

    if team_amount > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.fee_collector.to_account_info(),
                    to: ctx.accounts.team_vault.to_account_info(),
                },
                fee_vault_seeds,
            ),
            team_amount,
        )?;

        ctx.accounts.team_vault.total_collected = ctx.accounts.team_vault.total_collected
            .checked_add(team_amount)
            .ok_or(PowError::Overflow)?;

        config.total_team_fees = config.total_team_fees
            .checked_add(team_amount)
            .ok_or(PowError::Overflow)?;
    }

    // ==========================================================================
    // TREASURY (95%) — direct vers treasury_sol_vault
    // ==========================================================================

    if treasury_amount > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.fee_collector.to_account_info(),
                    to: ctx.accounts.treasury_sol_vault.to_account_info(),
                },
                fee_vault_seeds,
            ),
            treasury_amount,
        )?;

        config.total_buyback_sol = config.total_buyback_sol
            .checked_add(treasury_amount)
            .ok_or(PowError::Overflow)?;

        msg!("Treasury SOL sent: {} lamports", treasury_amount);
    }

    msg!("Fees distributed:");
    msg!("  Total: {} lamports", distributable);
    msg!("  Team (5%): {} lamports", team_amount);
    msg!("  Treasury (95%): {} lamports", treasury_amount);

    Ok(())
}

// =============================================================================
// CONTEXTES
// =============================================================================

#[derive(Accounts)]
pub struct DistributeFees<'info> {
    /// N'importe qui peut appeler cette instruction
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Configuration du protocole
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config.bump,
    )]
    pub pow_config: Box<Account<'info, PowConfig>>,

    /// Vault qui collecte les fees
    /// CHECK: PDA vérifié
    #[account(
        mut,
        seeds = [FEE_VAULT_SEED],
        bump,
    )]
    pub fee_collector: AccountInfo<'info>,

    /// Vault de la team
    #[account(
        mut,
        seeds = [TEAM_VAULT_SEED],
        bump,
    )]
    pub team_vault: Account<'info, TeamVault>,

    /// Treasury SOL vault (PDA de pow-treasury) — destination directe
    /// CHECK: Validé par PDA derivation contre le programme treasury
    #[account(
        mut,
        constraint = {
            let (expected, _) = Pubkey::find_program_address(
                &[TREASURY_SOL_VAULT_SEED],
                &TREASURY_PROGRAM_ID,
            );
            treasury_sol_vault.key() == expected
        } @ PowError::UnauthorizedTreasury,
    )]
    pub treasury_sol_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

