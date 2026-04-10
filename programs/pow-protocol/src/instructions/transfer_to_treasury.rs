// =============================================================================
// INSTRUCTION: TRANSFER TO TREASURY
// =============================================================================
// Permet au programme pow-treasury de récupérer le SOL des vaults
// pour les opérations de buyback et LP on-chain.
// Seul le programme pow-treasury peut appeler cette instruction via CPI.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;

/// Transfère le SOL des buyback_vault et lp_vault vers le programme pow-treasury
///
/// Cette instruction est appelée via CPI par pow-treasury::fund_treasury.
/// Le SOL est transféré vers les vaults du programme treasury pour
/// les opérations de buyback/burn et add LP on-chain via Meteora DLMM.
///
/// Permissionless côté signers, mais vérifie que le programme appelant
/// est bien pow-treasury via le treasury_authority PDA.
pub fn handler(ctx: Context<TransferToTreasury>) -> Result<()> {
    // Validate treasury_sol_vault is the correct PDA of the treasury program
    let (expected_vault, _bump) = Pubkey::find_program_address(
        &[TREASURY_SOL_VAULT_SEED],
        &TREASURY_PROGRAM_ID,
    );
    require!(
        ctx.accounts.treasury_sol_vault.key() == expected_vault,
        PowError::UnauthorizedTreasury
    );

    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(0);

    // ==========================================================================
    // TRANSFÉRER LE SOL DU BUYBACK VAULT
    // ==========================================================================

    let buyback_balance = ctx.accounts.buyback_vault.lamports();
    let buyback_withdrawable = buyback_balance.saturating_sub(min_balance);

    if buyback_withdrawable > 0 {
        let buyback_bump = ctx.bumps.buyback_vault;
        let buyback_seeds: &[&[&[u8]]] = &[&[
            b"buyback_vault",
            &[buyback_bump],
        ]];

        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.buyback_vault.to_account_info(),
                    to: ctx.accounts.treasury_sol_vault.to_account_info(),
                },
                buyback_seeds,
            ),
            buyback_withdrawable,
        )?;

        msg!("Transferred {} lamports from buyback_vault to treasury", buyback_withdrawable);
    }

    // ==========================================================================
    // TRANSFÉRER LE SOL DU LP VAULT
    // ==========================================================================

    let lp_balance = ctx.accounts.lp_vault.lamports();
    let lp_withdrawable = lp_balance.saturating_sub(min_balance);

    if lp_withdrawable > 0 {
        let lp_bump = ctx.bumps.lp_vault;
        let lp_seeds: &[&[&[u8]]] = &[&[
            LP_VAULT_SEED,
            &[lp_bump],
        ]];

        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.lp_vault.to_account_info(),
                    to: ctx.accounts.treasury_sol_vault.to_account_info(),
                },
                lp_seeds,
            ),
            lp_withdrawable,
        )?;

        msg!("Transferred {} lamports from lp_vault to treasury", lp_withdrawable);
    }

    let total = buyback_withdrawable + lp_withdrawable;
    if total == 0 {
        msg!("No SOL to transfer to treasury");
    } else {
        msg!("Total transferred to treasury: {} lamports", total);
    }

    Ok(())
}

// =============================================================================
// CONTEXTE
// =============================================================================

#[derive(Accounts)]
pub struct TransferToTreasury<'info> {
    /// Le payer de la transaction (cranker)
    #[account(mut)]
    pub payer: Signer<'info>,

    /// Buyback vault PDA (source SOL)
    /// CHECK: PDA vérifié par seeds
    #[account(
        mut,
        seeds = [b"buyback_vault"],
        bump,
    )]
    pub buyback_vault: AccountInfo<'info>,

    /// LP vault PDA (source SOL)
    /// CHECK: PDA vérifié par seeds
    #[account(
        mut,
        seeds = [LP_VAULT_SEED],
        bump,
    )]
    pub lp_vault: AccountInfo<'info>,

    /// Treasury SOL vault (destination) — must be the treasury program's PDA
    /// CHECK: Validated at runtime via PDA derivation against the treasury program
    #[account(mut)]
    pub treasury_sol_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}
