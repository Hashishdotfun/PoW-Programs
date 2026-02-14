// =============================================================================
// INSTRUCTION: SUBMIT PROOF
// =============================================================================
// Le cœur du système PoW - Soumet une preuve de travail valide
// Fonctionne pour les deux pools (normal et seeker)

use anchor_lang::prelude::*;
use solana_program::hash::hash;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{DeviceAttestation, MintAuthority, PowConfig, MinerStats};

pub fn handler(ctx: Context<SubmitProof>, nonce: u128) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;

    // ==========================================================================
    // VÉRIFICATIONS INITIALES
    // ==========================================================================

    require!(ctx.accounts.pow_config.is_initialized, PowError::NotInitialized);
    require!(!ctx.accounts.pow_config.is_paused, PowError::ProtocolPaused);

    // Combined supply check across both pools
    let combined_supply = ctx.accounts.pow_config.total_supply_mined
        .checked_add(ctx.accounts.other_pool.total_supply_mined)
        .ok_or(PowError::Overflow)?;
    require!(combined_supply < MAX_SUPPLY, PowError::MaxSupplyReached);

    // ==========================================================================
    // VÉRIFIER L'ATTESTATION DEVICE (seeker pool uniquement)
    // ==========================================================================

    if ctx.accounts.pow_config.pool_id == POOL_SEEKER {
        let attestation = ctx.accounts.attestation.as_mut()
            .ok_or(PowError::AttestationRequired)?;
        require!(
            !attestation.is_used,
            PowError::AttestationAlreadyUsed
        );
        require!(
            now - attestation.timestamp <= ATTESTATION_VALIDITY_SECS,
            PowError::AttestationExpired
        );
        require!(
            attestation.authority == ctx.accounts.pow_config.attestation_authority,
            PowError::InvalidAttestationAuthority
        );
        // Consume the attestation — miner must re-attest before next block
        attestation.is_used = true;
        msg!("Device attestation consumed (age: {}s)", now - attestation.timestamp);
    }

    let config = &mut ctx.accounts.pow_config;

    // ==========================================================================
    // VÉRIFIER LA PREUVE (PoW)
    // ==========================================================================

    let is_valid = verify_proof(
        &config.current_challenge,
        ctx.accounts.miner.key().as_ref(),
        nonce,
        config.blocks_mined,
        config.difficulty,
    )?;

    require!(is_valid, PowError::InvalidProof);

    // ==========================================================================
    // CALCULER ET COLLECTER LA FEE SOL
    // ==========================================================================

    let fee_sol = calculate_current_fee(config.launch_ts, now)?;

    anchor_lang::system_program::transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.miner.to_account_info(),
                to: ctx.accounts.fee_collector.to_account_info(),
            },
        ),
        fee_sol,
    )?;

    config.total_fees_collected = config.total_fees_collected
        .checked_add(fee_sol)
        .ok_or(PowError::Overflow)?;
    config.fee_sol_current = fee_sol;

    // ==========================================================================
    // CALCULER LE REWARD
    // ==========================================================================

    let base_reward = calculate_reward(
        config.blocks_mined,
        config.launch_ts,
        now,
    )?;

    let total_reward = base_reward
        .checked_add(config.pending_reward_tokens)
        .ok_or(PowError::Overflow)?;

    // Combined supply cap check
    let actual_reward = if combined_supply + total_reward > MAX_SUPPLY {
        MAX_SUPPLY - combined_supply
    } else {
        total_reward
    };

    config.pending_reward_tokens = 0;

    // ==========================================================================
    // MINT LES TOKENS AU MINEUR (via shared MintAuthority)
    // ==========================================================================

    if actual_reward > 0 {
        let new_total_supply = config.total_supply_mined
            .checked_add(actual_reward)
            .ok_or(PowError::Overflow)?;

        let mint_auth_bump = ctx.accounts.mint_authority.bump;
        let signer_seeds: &[&[&[u8]]] = &[&[
            MINT_AUTHORITY_SEED,
            &[mint_auth_bump],
        ]];

        anchor_spl::token_interface::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token_interface::MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.miner_token_account.to_account_info(),
                    authority: ctx.accounts.mint_authority.to_account_info(),
                },
                signer_seeds,
            ),
            actual_reward,
        )?;

        ctx.accounts.pow_config.total_supply_mined = new_total_supply;
    }

    // ==========================================================================
    // STOCKER LE TIMESTAMP DANS LE BUFFER CIRCULAIRE
    // ==========================================================================

    let config = &mut ctx.accounts.pow_config;
    let idx = config.block_timestamps_index as usize;
    config.block_timestamps[idx] = now;
    config.block_timestamps_index = ((idx + 1) % 10) as u8;
    if config.block_timestamps_count < 10 {
        config.block_timestamps_count += 1;
    }

    // ==========================================================================
    // AJUSTER LA DIFFICULTÉ
    // ==========================================================================

    config.difficulty = adjust_difficulty_with_average(
        config.difficulty,
        &config.block_timestamps,
        config.block_timestamps_count,
        now,
    )?;

    // ==========================================================================
    // METTRE À JOUR L'ÉTAT
    // ==========================================================================

    config.blocks_mined = config.blocks_mined
        .checked_add(1)
        .ok_or(PowError::Overflow)?;
    config.last_block_ts = now;

    ctx.accounts.pow_config.current_challenge = generate_new_challenge(
        &ctx.accounts.pow_config.current_challenge,
        nonce,
        clock.slot,
        ctx.accounts.pow_config.blocks_mined,
    );

    // ==========================================================================
    // METTRE À JOUR LES STATS DU MINEUR
    // ==========================================================================

    let miner_stats = &mut ctx.accounts.miner_stats;

    if miner_stats.blocks_mined == 0 {
        miner_stats.miner = ctx.accounts.miner.key();
        miner_stats.first_block_ts = now;
        miner_stats.bump = ctx.bumps.miner_stats;
        miner_stats.pool_id = ctx.accounts.pow_config.pool_id;
    }

    miner_stats.blocks_mined = miner_stats.blocks_mined
        .checked_add(1)
        .ok_or(PowError::Overflow)?;
    miner_stats.total_tokens_earned = miner_stats.total_tokens_earned
        .checked_add(actual_reward)
        .ok_or(PowError::Overflow)?;
    miner_stats.total_fees_paid = miner_stats.total_fees_paid
        .checked_add(fee_sol)
        .ok_or(PowError::Overflow)?;
    miner_stats.last_block_ts = now;

    // ==========================================================================
    // LOGS
    // ==========================================================================

    msg!("Pool {} Block #{} mined!", ctx.accounts.pow_config.pool_id, ctx.accounts.pow_config.blocks_mined);
    msg!("Miner: {}", ctx.accounts.miner.key());
    msg!("Reward: {} tokens", actual_reward);
    msg!("Fee paid: {} lamports", fee_sol);
    msg!("New difficulty: {}", ctx.accounts.pow_config.difficulty);
    msg!("Total supply mined (this pool): {}", ctx.accounts.pow_config.total_supply_mined);

    Ok(())
}

// =============================================================================
// FONCTIONS UTILITAIRES
// =============================================================================

fn verify_proof(challenge: &[u8; 32], miner_pubkey: &[u8], nonce: u128, blocks_mined: u64, difficulty: u128) -> Result<bool> {
    let mut message = Vec::with_capacity(88);
    message.extend_from_slice(challenge);
    message.extend_from_slice(miner_pubkey);
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&blocks_mined.to_le_bytes());

    msg!("DEBUG verify_proof:");
    msg!("  Challenge: {:?}", &challenge[..8]);
    msg!("  Miner: {:?}", &miner_pubkey[..8]);
    msg!("  Nonce: {}", nonce);
    msg!("  Blocks mined: {}", blocks_mined);
    msg!("  Message len: {}", message.len());

    let hash_result = hash(&message);
    let hash_bytes = hash_result.to_bytes();

    msg!("  Hash (first 16): {:?}", &hash_bytes[..16]);

    let hash_value = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());
    let target = u128::MAX / difficulty;

    msg!("  Hash value: {}", hash_value);
    msg!("  Target: {}", target);
    msg!("  Valid: {}", hash_value < target);

    Ok(hash_value < target)
}

fn calculate_reward(blocks_mined: u64, launch_ts: i64, now: i64) -> Result<u64> {
    let elapsed = now - launch_ts;

    let base_reward = if elapsed < BOOST_DURATION {
        R0_BOOST
    } else {
        R0_NORMAL
    };

    let full_groups = blocks_mined / 1000;
    let remaining_blocks = blocks_mined % 1000;

    const DECAY_1000_NUM: u128 = 999943;
    const DECAY_1000_DEN: u128 = 1000000;

    let mut reward = base_reward as u128;

    for _ in 0..full_groups.min(10000) {
        reward = reward
            .checked_mul(DECAY_1000_NUM)
            .ok_or(PowError::Overflow)?
            .checked_div(DECAY_1000_DEN)
            .ok_or(PowError::DivisionByZero)?;

        if reward < 1000 {
            break;
        }
    }

    const DECAY_100_NUM: u128 = 9999943;
    const DECAY_100_DEN: u128 = 10000000;

    let remaining_hundreds = remaining_blocks / 100;
    let final_blocks = remaining_blocks % 100;

    for _ in 0..remaining_hundreds {
        reward = reward
            .checked_mul(DECAY_100_NUM)
            .ok_or(PowError::Overflow)?
            .checked_div(DECAY_100_DEN)
            .ok_or(PowError::DivisionByZero)?;
    }

    for _ in 0..final_blocks {
        reward = reward
            .checked_mul(DECAY_FACTOR_NUMERATOR)
            .ok_or(PowError::Overflow)?
            .checked_div(DECAY_FACTOR_DENOMINATOR)
            .ok_or(PowError::DivisionByZero)?;
    }

    let final_reward = (reward as u64).max(1);
    let min_reward = DECIMALS_MULTIPLIER / 1000; // 0.001 token = 1_000_000

    Ok(final_reward.max(min_reward))
}

fn calculate_current_fee(launch_ts: i64, now: i64) -> Result<u64> {
    let elapsed = now - launch_ts;
    let two_years_in_seconds = 2 * SECONDS_PER_YEAR;
    let periods = (elapsed / two_years_in_seconds) as u32;

    let mut fee = FEE_INITIAL_SOL;

    for _ in 0..periods.min(10) {
        fee = fee
            .checked_mul(FEE_MULTIPLIER_NUMERATOR)
            .ok_or(PowError::Overflow)?
            .checked_div(FEE_MULTIPLIER_DENOMINATOR)
            .ok_or(PowError::DivisionByZero)?;

        if fee > FEE_SOL_CAP {
            fee = FEE_SOL_CAP;
            break;
        }
    }

    Ok(fee)
}

fn adjust_difficulty_with_average(
    current_difficulty: u128,
    block_timestamps: &[i64; 10],
    timestamps_count: u8,
    current_ts: i64,
) -> Result<u128> {
    if timestamps_count < 2 {
        return Ok(current_difficulty);
    }

    let count = timestamps_count as usize;

    let oldest_ts = block_timestamps.iter()
        .take(count)
        .copied()
        .filter(|&ts| ts > 0)
        .min()
        .unwrap_or(current_ts);

    let total_time = current_ts.saturating_sub(oldest_ts);
    let intervals = count.saturating_sub(1) as i64;
    if intervals <= 0 {
        return Ok(current_difficulty);
    }

    let avg_block_time = total_time / intervals;

    msg!("Difficulty adjustment: {} blocks, {}s total, {}s avg (target: {}s)",
        count, total_time, avg_block_time, TARGET_BLOCK_TIME);

    let avg_u128 = avg_block_time.max(1) as u128;
    let target_u128 = TARGET_BLOCK_TIME as u128;

    let ratio_x1000 = avg_u128
        .checked_mul(1000)
        .ok_or(PowError::Overflow)?
        .checked_div(target_u128)
        .ok_or(PowError::DivisionByZero)?;

    let (adjustment_num, adjustment_den): (u128, u128) = if ratio_x1000 < 500 {
        (3, 2)
    } else if ratio_x1000 < 750 {
        (5, 4)
    } else if ratio_x1000 < 900 {
        (11, 10)
    } else if ratio_x1000 <= 1100 {
        (1, 1)
    } else if ratio_x1000 <= 1333 {
        (9, 10)
    } else if ratio_x1000 <= 2000 {
        (4, 5)
    } else {
        (2, 3)
    };

    msg!("Ratio x1000: {}, adjustment: {}/{}", ratio_x1000, adjustment_num, adjustment_den);

    let new_difficulty = current_difficulty
        .checked_mul(adjustment_num)
        .ok_or(PowError::Overflow)?
        .checked_div(adjustment_den)
        .ok_or(PowError::DivisionByZero)?;

    Ok(new_difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY))
}

fn generate_new_challenge(old_challenge: &[u8; 32], nonce: u128, slot: u64, block_number: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(old_challenge);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&slot.to_le_bytes());
    data.extend_from_slice(&block_number.to_le_bytes());

    hash(&data).to_bytes()
}

// =============================================================================
// CONTEXTE DE L'INSTRUCTION
// =============================================================================

#[derive(Accounts)]
pub struct SubmitProof<'info> {
    /// Le mineur qui soumet la preuve
    #[account(mut)]
    pub miner: Signer<'info>,

    /// Configuration de la pool minée (writable)
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[pow_config.pool_id]],
        bump = pow_config.bump,
        has_one = mint @ PowError::InvalidMint,
    )]
    pub pow_config: Account<'info, PowConfig>,

    /// L'autre pool (read-only, pour vérifier le supply cap combiné)
    #[account(
        seeds = [POW_CONFIG_SEED, &[other_pool.pool_id]],
        bump = other_pool.bump,
        constraint = other_pool.pool_id != pow_config.pool_id @ PowError::InvalidPoolId,
    )]
    pub other_pool: Account<'info, PowConfig>,

    /// Shared mint authority (signe les mint_to CPI)
    #[account(
        seeds = [MINT_AUTHORITY_SEED],
        bump = mint_authority.bump,
    )]
    pub mint_authority: Account<'info, MintAuthority>,

    /// Le mint du token
    #[account(
        mut,
        mint::token_program = token_program,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Token account du mineur (reçoit les rewards)
    #[account(
        mut,
        token::mint = mint,
        token::authority = miner,
        token::token_program = token_program,
    )]
    pub miner_token_account: InterfaceAccount<'info, TokenAccount>,

    /// Statistiques du mineur pour cette pool (PDA)
    #[account(
        init_if_needed,
        payer = miner,
        space = MinerStats::LEN,
        seeds = [MINER_STATS_SEED, &[pow_config.pool_id], miner.key().as_ref()],
        bump,
    )]
    pub miner_stats: Account<'info, MinerStats>,

    /// Compte qui collecte les fees (PDA du programme, partagé)
    /// CHECK: PDA vérifié par seeds
    #[account(
        mut,
        seeds = [FEE_VAULT_SEED],
        bump,
    )]
    pub fee_collector: AccountInfo<'info>,

    /// Attestation device du mineur (optionnel, requis uniquement pour la pool seeker)
    #[account(
        mut,
        seeds = [DEVICE_ATTEST_SEED, miner.key().as_ref()],
        bump,
    )]
    pub attestation: Option<Account<'info, DeviceAttestation>>,

    /// Programme Token
    pub token_program: Interface<'info, TokenInterface>,

    /// Programme System
    pub system_program: Program<'info, System>,
}
