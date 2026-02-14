// =============================================================================
// INSTRUCTION: UPDATE CONFIG
// =============================================================================
// Permet à l'autorité de mettre à jour certains paramètres du protocole

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;

/// Paramètres optionnels de mise à jour
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default)]
pub struct UpdateConfigParams {
    /// Nouvelle autorité (si Some)
    pub new_authority: Option<Pubkey>,

    /// Nouvelle difficulté minimum
    pub new_min_difficulty: Option<u128>,

    /// Mettre en pause / reprendre
    pub pause: Option<bool>,

    /// Backend pubkey autorisée à créer des attestations device
    /// Set to Some(Pubkey::default()) to disable attestation requirement
    pub attestation_authority: Option<Pubkey>,
}

/// Met à jour la configuration du protocole
/// 
/// Seule l'autorité peut appeler cette instruction
/// Certains paramètres sont immuables pour garantir la confiance
pub fn handler(ctx: Context<UpdateConfig>, params: UpdateConfigParams) -> Result<()> {
    let config = &mut ctx.accounts.pow_config;

    // Vérifier que l'appelant est l'autorité
    require!(
        ctx.accounts.authority.key() == config.authority,
        PowError::Unauthorized
    );

    // ==========================================================================
    // MISE À JOUR DES PARAMÈTRES
    // ==========================================================================

    // Nouvelle autorité
    if let Some(new_authority) = params.new_authority {
        msg!("Updating authority from {} to {}", config.authority, new_authority);
        config.authority = new_authority;
    }

    // Nouvelle difficulté minimum (pour débugger si nécessaire)
    if let Some(new_min_diff) = params.new_min_difficulty {
        require!(
            new_min_diff >= 100 && new_min_diff <= MAX_DIFFICULTY,
            PowError::InvalidDifficulty
        );
        
        // On ne peut que diminuer la difficulté actuelle, pas l'augmenter arbitrairement
        if config.difficulty < new_min_diff {
            msg!("Adjusting difficulty from {} to {}", config.difficulty, new_min_diff);
            config.difficulty = new_min_diff;
        }
    }

    // Pause / Resume
    if let Some(pause) = params.pause {
        msg!("Protocol pause state: {} -> {}", config.is_paused, pause);
        config.is_paused = pause;
    }

    // Attestation authority
    if let Some(attest_auth) = params.attestation_authority {
        msg!("Attestation authority: {} -> {}", config.attestation_authority, attest_auth);
        config.attestation_authority = attest_auth;
    }

    msg!("Config updated successfully");

    Ok(())
}

/// Transfère l'autorité à une nouvelle adresse
/// 
/// Pattern de sécurité: l'ancienne et la nouvelle autorité doivent signer
pub fn transfer_authority(ctx: Context<TransferAuthority>) -> Result<()> {
    let config = &mut ctx.accounts.pow_config;

    // Vérifier que l'ancienne autorité est correcte
    require!(
        ctx.accounts.current_authority.key() == config.authority,
        PowError::Unauthorized
    );

    // Transférer l'autorité
    let new_authority = ctx.accounts.new_authority.key();
    msg!(
        "Transferring authority from {} to {}",
        config.authority,
        new_authority
    );
    
    config.authority = new_authority;

    Ok(())
}

/// Met à jour le pending_reward (appelé par le transfer hook)
/// 
/// Cette fonction est appelée quand la taxe de transfert est collectée
/// pour ajouter des tokens au pool de reward des mineurs
pub fn add_pending_reward(ctx: Context<AddPendingReward>, amount: u64) -> Result<()> {
    let config = &mut ctx.accounts.pow_config;

    // Seul le programme transfer hook peut appeler cette fonction
    // En production, vérifier que l'appelant est bien le transfer hook

    config.pending_reward_tokens = config.pending_reward_tokens
        .checked_add(amount)
        .ok_or(PowError::Overflow)?;

    msg!("Added {} tokens to pending reward pool", amount);
    msg!("Total pending: {}", config.pending_reward_tokens);

    Ok(())
}

/// Incrémente le compteur de tokens brûlés via la taxe transfert
pub fn record_transfer_burn(ctx: Context<RecordTransferBurn>, amount: u64) -> Result<()> {
    let config = &mut ctx.accounts.pow_config;

    config.total_burned_from_transfer_tax = config.total_burned_from_transfer_tax
        .checked_add(amount)
        .ok_or(PowError::Overflow)?;

    msg!("Recorded {} tokens burned from transfer tax", amount);
    msg!("Total burned from transfer tax: {}", config.total_burned_from_transfer_tax);

    Ok(())
}

// =============================================================================
// CONTEXTES
// =============================================================================

#[derive(Accounts)]
pub struct UpdateConfig<'info> {
    /// L'autorité actuelle du protocole
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Configuration du protocole
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[pow_config.pool_id]],
        bump = pow_config.bump,
        has_one = authority @ PowError::Unauthorized,
    )]
    pub pow_config: Account<'info, PowConfig>,
}

#[derive(Accounts)]
pub struct TransferAuthority<'info> {
    /// L'autorité actuelle
    pub current_authority: Signer<'info>,

    /// La nouvelle autorité (doit aussi signer)
    pub new_authority: Signer<'info>,

    /// Configuration du protocole
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[pow_config.pool_id]],
        bump = pow_config.bump,
    )]
    pub pow_config: Account<'info, PowConfig>,
}

#[derive(Accounts)]
pub struct AddPendingReward<'info> {
    /// Le programme transfer hook ou autorité
    pub caller: Signer<'info>,

    /// Configuration du protocole
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[pow_config.pool_id]],
        bump = pow_config.bump,
    )]
    pub pow_config: Account<'info, PowConfig>,
}

#[derive(Accounts)]
pub struct RecordTransferBurn<'info> {
    /// Le programme transfer hook ou autorité
    pub caller: Signer<'info>,

    /// Configuration du protocole
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[pow_config.pool_id]],
        bump = pow_config.bump,
    )]
    pub pow_config: Account<'info, PowConfig>,
}
