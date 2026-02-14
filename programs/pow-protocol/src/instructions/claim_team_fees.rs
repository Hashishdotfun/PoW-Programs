// =============================================================================
// INSTRUCTION: CLAIM TEAM FEES
// =============================================================================
// Permet à l'autorité de retirer les fees accumulées pour la team

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;
use crate::instructions::initialize::TeamVault;

/// Retire les fees accumulées dans le vault team
/// 
/// Seule l'autorité du protocole peut retirer les fees
/// Les fees sont transférées vers le wallet spécifié
pub fn handler(ctx: Context<ClaimTeamFees>, amount: Option<u64>) -> Result<()> {
    let _team_vault = &ctx.accounts.team_vault;
    let config = &ctx.accounts.pow_config;

    // Vérifier que l'appelant est l'autorité
    require!(
        ctx.accounts.authority.key() == config.authority,
        PowError::Unauthorized
    );

    // Calculer le montant retirable
    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(TeamVault::LEN);
    
    let vault_balance = ctx.accounts.team_vault.to_account_info().lamports();
    let available = vault_balance
        .checked_sub(min_balance)
        .ok_or(PowError::EmptyFeeVault)?;

    // Déterminer le montant à retirer
    let withdraw_amount = match amount {
        Some(requested) => {
            require!(requested <= available, PowError::InsufficientFeePayment);
            requested
        }
        None => available, // Retirer tout si pas de montant spécifié
    };

    if withdraw_amount == 0 {
        msg!("No fees to claim");
        return Ok(());
    }

    // Transférer les lamports
    **ctx.accounts.team_vault.to_account_info().try_borrow_mut_lamports()? -= withdraw_amount;
    **ctx.accounts.recipient.try_borrow_mut_lamports()? += withdraw_amount;

    msg!("Team fees claimed: {} lamports", withdraw_amount);
    msg!("Recipient: {}", ctx.accounts.recipient.key());
    msg!("Remaining in vault: {} lamports", vault_balance - withdraw_amount);

    Ok(())
}

/// Vue des stats du vault team (read-only)
pub fn get_team_vault_stats(ctx: Context<GetTeamVaultStats>) -> Result<TeamVaultStats> {
    let team_vault = &ctx.accounts.team_vault;
    let config = &ctx.accounts.pow_config;

    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(TeamVault::LEN);
    let vault_balance = team_vault.to_account_info().lamports();
    let available = vault_balance.saturating_sub(min_balance);

    Ok(TeamVaultStats {
        total_collected: team_vault.total_collected,
        current_balance: vault_balance,
        available_to_claim: available,
        authority: config.authority,
    })
}

/// Stats du vault team
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TeamVaultStats {
    pub total_collected: u64,
    pub current_balance: u64,
    pub available_to_claim: u64,
    pub authority: Pubkey,
}

// =============================================================================
// CONTEXTES
// =============================================================================

#[derive(Accounts)]
pub struct ClaimTeamFees<'info> {
    /// L'autorité du protocole
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Configuration du protocole (pour vérifier l'autorité)
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config.bump,
        has_one = authority @ PowError::Unauthorized,
    )]
    pub pow_config: Account<'info, PowConfig>,

    /// Vault de la team
    #[account(
        mut,
        seeds = [TEAM_VAULT_SEED],
        bump,
    )]
    pub team_vault: Account<'info, TeamVault>,

    /// Destinataire des fees
    /// CHECK: N'importe quelle adresse valide
    #[account(mut)]
    pub recipient: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct GetTeamVaultStats<'info> {
    /// Configuration du protocole
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config.bump,
    )]
    pub pow_config: Account<'info, PowConfig>,

    /// Vault de la team
    #[account(
        seeds = [TEAM_VAULT_SEED],
        bump,
    )]
    pub team_vault: Account<'info, TeamVault>,
}
