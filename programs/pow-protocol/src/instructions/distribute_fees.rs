// =============================================================================
// INSTRUCTION: DISTRIBUTE FEES
// =============================================================================
// Distribue les fees SOL collectées selon le modèle économique:
// - 5% team
// - 95% protocol: 60% buyback (50% burn, 50% LP) + 40% LP direct

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, Burn, burn};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;
use crate::instructions::initialize::TeamVault;

/// Distribue les fees SOL accumulées
/// 
/// Cette instruction peut être appelée par n'importe qui (permissionless)
/// Elle distribue les fees collectées dans le fee_collector selon:
/// - 5% → team_vault
/// - 57% → buyback (60% * 95%) → dont 50% burn, 50% LP
/// - 38% → LP direct (40% * 95%)
/// 
/// Note: L'intégration AMM (buyback, add liquidity) est simplifiée ici
/// En production, il faudrait intégrer Raydium, Orca, ou un autre AMM
pub fn handler(ctx: Context<DistributeFees>) -> Result<()> {
    let fee_collector = &ctx.accounts.fee_collector;
    let fee_balance = fee_collector.lamports();
    
    // Garder un minimum pour le rent
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

    // ==========================================================================
    // CALCULER LES SPLITS
    // ==========================================================================
    
    // 5% pour la team
    let team_amount = distributable
        .checked_mul(TEAM_FEE_PCT)
        .ok_or(PowError::Overflow)?
        .checked_div(100)
        .ok_or(PowError::DivisionByZero)?;
    
    // 95% pour le protocol
    let protocol_amount = distributable
        .checked_sub(team_amount)
        .ok_or(PowError::Underflow)?;
    
    // 60% du protocol pour buyback
    let buyback_amount = protocol_amount
        .checked_mul(BUYBACK_SOL_PCT)
        .ok_or(PowError::Overflow)?
        .checked_div(100)
        .ok_or(PowError::DivisionByZero)?;
    
    // 40% du protocol pour LP direct
    let lp_direct_amount = protocol_amount
        .checked_sub(buyback_amount)
        .ok_or(PowError::Underflow)?;

    // ==========================================================================
    // TRANSFÉRER À LA TEAM (via CPI avec PDA signature)
    // ==========================================================================

    // Seeds pour signer en tant que fee_collector PDA
    let fee_vault_bump = ctx.bumps.fee_collector;
    let fee_vault_seeds: &[&[&[u8]]] = &[&[
        FEE_VAULT_SEED,
        &[fee_vault_bump],
    ]];

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
    // BUYBACK - Transférer vers le vault pour swap ultérieur
    // ==========================================================================

    if buyback_amount > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.fee_collector.to_account_info(),
                    to: ctx.accounts.buyback_vault.to_account_info(),
                },
                fee_vault_seeds,
            ),
            buyback_amount,
        )?;

        config.total_buyback_sol = config.total_buyback_sol
            .checked_add(buyback_amount)
            .ok_or(PowError::Overflow)?;

        msg!("Buyback SOL queued: {} lamports", buyback_amount);
    }

    // ==========================================================================
    // LP DIRECT - Transférer vers le vault pour ajout de liquidité ultérieur
    // ==========================================================================

    if lp_direct_amount > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.fee_collector.to_account_info(),
                    to: ctx.accounts.lp_vault.to_account_info(),
                },
                fee_vault_seeds,
            ),
            lp_direct_amount,
        )?;

        config.total_lp_sol = config.total_lp_sol
            .checked_add(lp_direct_amount)
            .ok_or(PowError::Overflow)?;

        msg!("LP SOL queued: {} lamports", lp_direct_amount);
    }

    // ==========================================================================
    // LOGS
    // ==========================================================================

    msg!("Fees distributed:");
    msg!("  Total: {} lamports", distributable);
    msg!("  Team (5%): {} lamports", team_amount);
    msg!("  Buyback (57%): {} lamports", buyback_amount);
    msg!("  LP Direct (38%): {} lamports", lp_direct_amount);

    Ok(())
}

// =============================================================================
// EXECUTE BUYBACK - Swap SOL → Token puis burn 50%
// =============================================================================
// NOTE: Le swap réel sera fait off-chain via script TypeScript
// car l'intégration CPI Raydium est complexe.
// Cette instruction permet de récupérer les stats et vérifier les montants.

/// Enregistre l'exécution d'un buyback (appelé après swap off-chain)
/// Les tokens achetés sont envoyés dans token_vault, puis:
/// - 50% sont brûlés
/// - 50% restent pour LP
pub fn execute_buyback(ctx: Context<ExecuteBuyback>) -> Result<()> {
    let token_vault = &ctx.accounts.token_vault;
    let tokens_in_vault = token_vault.amount;

    if tokens_in_vault == 0 {
        msg!("No tokens to process in buyback vault");
        return Ok(());
    }

    // Calculer les parts
    let burn_amount = tokens_in_vault / 2;
    let lp_amount = tokens_in_vault - burn_amount;

    msg!("Processing buyback tokens:");
    msg!("  Total in vault: {} tokens", tokens_in_vault);
    msg!("  To burn (50%): {} tokens", burn_amount);
    msg!("  To LP (50%): {} tokens", lp_amount);

    // ==========================================================================
    // BURN 50% DES TOKENS
    // ==========================================================================

    if burn_amount > 0 {
        let config = &ctx.accounts.pow_config;
        let signer_seeds: &[&[&[u8]]] = &[&[
            POW_CONFIG_SEED,
            &[config.bump],
        ]];

        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.token_vault.to_account_info(),
                    authority: ctx.accounts.pow_config.to_account_info(),
                },
                signer_seeds,
            ),
            burn_amount,
        )?;

        let config = &mut ctx.accounts.pow_config;
        config.total_burned_from_buyback = config.total_burned_from_buyback
            .checked_add(burn_amount)
            .ok_or(PowError::Overflow)?;

        msg!("Burned {} tokens from buyback", burn_amount);
    }

    // Les 50% restants (lp_amount) restent dans le vault pour LP
    msg!("{} tokens available for LP", lp_amount);

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
    pub pow_config: Account<'info, PowConfig>,

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

    /// Vault pour le buyback
    /// CHECK: PDA vérifié
    #[account(
        mut,
        seeds = [b"buyback_vault"],
        bump,
    )]
    pub buyback_vault: AccountInfo<'info>,

    /// Vault pour la LP
    /// CHECK: PDA vérifié
    #[account(
        mut,
        seeds = [LP_VAULT_SEED],
        bump,
    )]
    pub lp_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ExecuteBuyback<'info> {
    /// N'importe qui peut appeler (permissionless)
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config.bump,
    )]
    pub pow_config: Account<'info, PowConfig>,

    #[account(mut)]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Vault qui contient les tokens achetés via swap off-chain
    /// Authority = pow_config PDA
    #[account(
        mut,
        token::mint = mint,
        token::authority = pow_config,
        token::token_program = token_program,
    )]
    pub token_vault: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
}

// =============================================================================
// WITHDRAW FOR BUYBACK - Retire le SOL du buyback_vault pour le swap
// =============================================================================

/// Permet au keeper de retirer le SOL du buyback_vault pour faire le swap off-chain
/// Le keeper doit ensuite faire le swap et appeler execute_buyback
///
/// Permissionless - n'importe qui peut appeler (incentive: ils gardent une partie)
pub fn withdraw_for_buyback(ctx: Context<WithdrawForBuyback>) -> Result<()> {
    let buyback_vault = &ctx.accounts.buyback_vault;
    let balance = buyback_vault.lamports();

    // Garder le minimum pour le rent
    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(0);

    let withdrawable = balance
        .checked_sub(min_balance)
        .ok_or(PowError::EmptyFeeVault)?;

    if withdrawable == 0 {
        msg!("No SOL to withdraw from buyback vault");
        return Ok(());
    }

    // Transférer vers le keeper
    let buyback_bump = ctx.bumps.buyback_vault;
    let signer_seeds: &[&[&[u8]]] = &[&[
        b"buyback_vault",
        &[buyback_bump],
    ]];

    anchor_lang::system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.buyback_vault.to_account_info(),
                to: ctx.accounts.keeper.to_account_info(),
            },
            signer_seeds,
        ),
        withdrawable,
    )?;

    msg!("Withdrew {} lamports from buyback_vault to keeper", withdrawable);

    Ok(())
}

/// Permet au keeper de retirer le SOL du lp_vault pour ajouter de la liquidité
pub fn withdraw_for_lp(ctx: Context<WithdrawForLp>) -> Result<()> {
    let lp_vault = &ctx.accounts.lp_vault;
    let balance = lp_vault.lamports();

    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(0);

    let withdrawable = balance
        .checked_sub(min_balance)
        .ok_or(PowError::EmptyFeeVault)?;

    if withdrawable == 0 {
        msg!("No SOL to withdraw from LP vault");
        return Ok(());
    }

    let lp_bump = ctx.bumps.lp_vault;
    let signer_seeds: &[&[&[u8]]] = &[&[
        LP_VAULT_SEED,
        &[lp_bump],
    ]];

    anchor_lang::system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.lp_vault.to_account_info(),
                to: ctx.accounts.keeper.to_account_info(),
            },
            signer_seeds,
        ),
        withdrawable,
    )?;

    msg!("Withdrew {} lamports from lp_vault to keeper", withdrawable);

    Ok(())
}

#[derive(Accounts)]
pub struct WithdrawForBuyback<'info> {
    /// Le keeper qui va faire le swap
    #[account(mut)]
    pub keeper: Signer<'info>,

    /// Buyback vault PDA
    /// CHECK: PDA vérifié par seeds
    #[account(
        mut,
        seeds = [b"buyback_vault"],
        bump,
    )]
    pub buyback_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawForLp<'info> {
    /// Le keeper qui va ajouter la liquidité
    #[account(mut)]
    pub keeper: Signer<'info>,

    /// LP vault PDA
    /// CHECK: PDA vérifié par seeds
    #[account(
        mut,
        seeds = [LP_VAULT_SEED],
        bump,
    )]
    pub lp_vault: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}
