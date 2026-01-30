// =============================================================================
// INSTRUCTION: INITIALIZE
// =============================================================================
// Initialise le protocole PoW avec tous les paramètres de base

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;

/// Initialise le protocole PoW
/// 
/// Cette instruction doit être appelée une seule fois après le déploiement
/// Elle configure tous les paramètres initiaux et crée les PDAs nécessaires
pub fn handler(ctx: Context<Initialize>) -> Result<()> {
    let config = &mut ctx.accounts.pow_config;
    let clock = Clock::get()?;

    // Vérifier que le protocole n'est pas déjà initialisé
    require!(!config.is_initialized, PowError::AlreadyInitialized);

    // Générer le challenge initial (basé sur le slot actuel)
    let initial_challenge = generate_initial_challenge(clock.slot, clock.unix_timestamp);

    // Initialiser la configuration
    config.authority = ctx.accounts.authority.key();
    config.mint = ctx.accounts.mint.key();
    
    // État du mining
    config.difficulty = INITIAL_DIFFICULTY;
    config.last_block_ts = clock.unix_timestamp;
    config.blocks_mined = 0;
    config.total_supply_mined = 0;
    config.current_challenge = initial_challenge;
    
    // Rewards
    config.pending_reward_tokens = 0;
    
    // Fees
    config.fee_sol_current = FEE_INITIAL_SOL;
    config.total_fees_collected = 0;
    config.total_team_fees = 0;
    config.total_buyback_sol = 0;
    config.total_lp_sol = 0;
    
    // Burns
    config.total_burned_from_buyback = 0;
    config.total_burned_from_transfer_tax = 0;
    
    // Timestamps
    config.launch_ts = clock.unix_timestamp;
    config.last_fee_update_ts = clock.unix_timestamp;
    
    // Flags
    config.is_initialized = true;
    config.is_paused = false;
    config.bump = ctx.bumps.pow_config;

    // Difficulty moving average buffer (init with launch timestamp)
    config.block_timestamps = [clock.unix_timestamp; 10];
    config.block_timestamps_index = 0;
    config.block_timestamps_count = 1; // Start with 1 timestamp (launch)

    msg!("PoW Protocol initialized!");
    msg!("Authority: {}", config.authority);
    msg!("Mint: {}", config.mint);
    msg!("Initial difficulty: {}", config.difficulty);
    msg!("Initial fee: {} lamports", config.fee_sol_current);
    msg!("Launch timestamp: {}", config.launch_ts);

    Ok(())
}

/// Génère le challenge initial basé sur le slot et le timestamp
///
/// Pour le bloc genesis (bloc 0), on utilise le slot et le timestamp comme entropie
fn generate_initial_challenge(slot: u64, timestamp: i64) -> [u8; 32] {
    use solana_program::hash::hash;

    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&slot.to_le_bytes());      // 8 bytes - Slot Solana
    data.extend_from_slice(&timestamp.to_le_bytes()); // 8 bytes - Unix timestamp
    data.extend_from_slice(&0u64.to_le_bytes());      // 8 bytes - Block 0 (genesis)

    hash(&data).to_bytes()
}

// =============================================================================
// CONTEXTE DE L'INSTRUCTION
// =============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// L'autorité qui initialise le protocole (devient l'admin)
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Le mint du token SPL2022
    /// On vérifie qu'il a bien 9 décimales
    #[account(
        mint::token_program = token_program,
        constraint = mint.decimals == DECIMALS @ PowError::InvalidMint,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Configuration principale du protocole (PDA)
    #[account(
        init,
        payer = authority,
        space = PowConfig::LEN,
        seeds = [POW_CONFIG_SEED],
        bump,
    )]
    pub pow_config: Account<'info, PowConfig>,

    /// Vault pour stocker les tokens (rewards pour mineurs)
    #[account(
        init,
        payer = authority,
        seeds = [POW_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pow_vault,
        token::token_program = token_program,
    )]
    pub pow_vault: InterfaceAccount<'info, TokenAccount>,

    /// Vault pour collecter les fees team
    #[account(
        init,
        payer = authority,
        seeds = [TEAM_VAULT_SEED],
        bump,
        space = 8 + 8, // discriminator + lamports tracking
    )]
    pub team_vault: Account<'info, TeamVault>,

    /// Programme Token (SPL Token 2022)
    pub token_program: Interface<'info, TokenInterface>,
    
    /// Programme System
    pub system_program: Program<'info, System>,
}

/// Vault simple pour tracker les fees team
#[account]
#[derive(Default)]
pub struct TeamVault {
    pub total_collected: u64,
}

impl TeamVault {
    pub const LEN: usize = 8 + 8;
}
