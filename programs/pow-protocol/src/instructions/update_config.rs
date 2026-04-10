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

    /// Register preminted supply against the max supply cap.
    /// Can only be set once (when total_supply_mined == 0) and only on pool 0.
    /// The amount is added to total_supply_mined so miners can only mine MAX_SUPPLY - premint.
    pub premint_supply: Option<u64>,
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

    // Register preminted supply (one-time, pool 0 only)
    if let Some(premint) = params.premint_supply {
        require!(config.pool_id == POOL_NORMAL, PowError::InvalidPoolId);
        require!(config.total_supply_mined == 0, PowError::AlreadyInitialized);
        require!(premint > 0 && premint < MAX_SUPPLY, PowError::Overflow);
        config.total_supply_mined = premint;
        msg!("Premint supply registered: {} tokens against max supply cap", premint);
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


/// Enregistre les tokens brûlés via le treasury buyback et libère du cap supply.
/// Le montant est splitté 50/50 entre pool normal et pool seeker.
/// Callable par le treasury_config PDA du programme pow-treasury.
pub fn record_treasury_burn(ctx: Context<RecordTreasuryBurn>, amount: u64) -> Result<()> {
    // Verify caller is the pow-treasury treasury_config PDA
    let (expected_treasury_config, _bump) = Pubkey::find_program_address(
        &[b"treasury_config"],
        &TREASURY_PROGRAM_ID,
    );
    require!(
        *ctx.accounts.caller.key == expected_treasury_config,
        PowError::Unauthorized
    );

    let normal_share = amount / 2;
    let seeker_share = amount.checked_sub(normal_share).ok_or(PowError::Underflow)?;

    let config_normal = &mut ctx.accounts.pow_config_normal;
    config_normal.total_burned_from_buyback = config_normal.total_burned_from_buyback
        .checked_add(normal_share)
        .ok_or(PowError::Overflow)?;
    config_normal.total_supply_mined = config_normal.total_supply_mined
        .saturating_sub(normal_share);

    let config_seeker = &mut ctx.accounts.pow_config_seeker;
    config_seeker.total_burned_from_buyback = config_seeker.total_burned_from_buyback
        .checked_add(seeker_share)
        .ok_or(PowError::Overflow)?;
    config_seeker.total_supply_mined = config_seeker.total_supply_mined
        .saturating_sub(seeker_share);

    msg!("Treasury burn: {} freed from supply cap ({} normal, {} seeker)", amount, normal_share, seeker_share);

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
    pub pow_config: Box<Account<'info, PowConfig>>,
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
    pub pow_config: Box<Account<'info, PowConfig>>,
}

#[derive(Accounts)]
pub struct RecordTreasuryBurn<'info> {
    /// Must be the pow-treasury treasury_config PDA (verified in handler)
    pub caller: Signer<'info>,

    /// Configuration du pool normal (pool 0)
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config_normal.bump,
    )]
    pub pow_config_normal: Box<Account<'info, PowConfig>>,

    /// Configuration du pool seeker (pool 1)
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[POOL_SEEKER]],
        bump = pow_config_seeker.bump,
    )]
    pub pow_config_seeker: Box<Account<'info, PowConfig>>,
}

