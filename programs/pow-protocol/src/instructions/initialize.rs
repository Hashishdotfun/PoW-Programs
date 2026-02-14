// =============================================================================
// INSTRUCTION: INITIALIZE
// =============================================================================
// Initialise une pool du protocole PoW. Appelé 2 fois: pool 0 (normal) + pool 1 (seeker)

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{MintAuthority, PowConfig};

/// Initialise une pool du protocole PoW
///
/// Appelée deux fois:
/// - `initialize(0)` → crée pool normale + MintAuthority + pow_vault + team_vault
/// - `initialize(1)` → crée pool seeker (shared accounts déjà créés via init_if_needed)
pub fn handler(ctx: Context<Initialize>, pool_id: u8) -> Result<()> {
    require!(pool_id <= POOL_SEEKER, PowError::InvalidPoolId);

    let config = &mut ctx.accounts.pow_config;
    let clock = Clock::get()?;

    // Vérifier que la pool n'est pas déjà initialisée
    require!(!config.is_initialized, PowError::AlreadyInitialized);

    // Générer le challenge initial (basé sur le slot actuel + pool_id pour unicité)
    let initial_challenge = generate_initial_challenge(clock.slot, clock.unix_timestamp, pool_id);

    // Initialiser la configuration
    config.authority = ctx.accounts.authority.key();
    config.mint = ctx.accounts.mint.key();
    config.pool_id = pool_id;

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
    config.block_timestamps_count = 1;

    // Init mint authority bump (idempotent via init_if_needed)
    let mint_auth = &mut ctx.accounts.mint_authority;
    if mint_auth.bump == 0 {
        mint_auth.bump = ctx.bumps.mint_authority;
    }

    msg!("Pool {} initialized!", pool_id);
    msg!("Authority: {}", config.authority);
    msg!("Mint: {}", config.mint);
    msg!("Initial difficulty: {}", config.difficulty);
    msg!("Initial fee: {} lamports", config.fee_sol_current);

    Ok(())
}

/// Génère le challenge initial basé sur le slot, timestamp et pool_id
fn generate_initial_challenge(slot: u64, timestamp: i64, pool_id: u8) -> [u8; 32] {
    use solana_program::hash::hash;

    let mut data = Vec::with_capacity(25);
    data.extend_from_slice(&slot.to_le_bytes());
    data.extend_from_slice(&timestamp.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // Block 0 (genesis)
    data.push(pool_id); // Different challenge per pool

    hash(&data).to_bytes()
}

// =============================================================================
// CONTEXTE DE L'INSTRUCTION
// =============================================================================

#[derive(Accounts)]
#[instruction(pool_id: u8)]
pub struct Initialize<'info> {
    /// L'autorité qui initialise le protocole (devient l'admin)
    #[account(mut)]
    pub authority: Signer<'info>,

    /// Le mint du token SPL2022
    #[account(
        mint::token_program = token_program,
        constraint = mint.decimals == DECIMALS @ PowError::InvalidMint,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Configuration de la pool (PDA avec pool_id)
    #[account(
        init,
        payer = authority,
        space = PowConfig::LEN,
        seeds = [POW_CONFIG_SEED, &[pool_id]],
        bump,
    )]
    pub pow_config: Account<'info, PowConfig>,

    /// Shared mint authority (created on first call, reused on second)
    #[account(
        init_if_needed,
        payer = authority,
        space = MintAuthority::LEN,
        seeds = [MINT_AUTHORITY_SEED],
        bump,
    )]
    pub mint_authority: Account<'info, MintAuthority>,

    /// Vault pour stocker les tokens (shared, created on first call)
    #[account(
        init_if_needed,
        payer = authority,
        seeds = [POW_VAULT_SEED, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pow_vault,
        token::token_program = token_program,
    )]
    pub pow_vault: InterfaceAccount<'info, TokenAccount>,

    /// Vault pour collecter les fees team (shared, created on first call)
    #[account(
        init_if_needed,
        payer = authority,
        seeds = [TEAM_VAULT_SEED],
        bump,
        space = 8 + 8,
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
