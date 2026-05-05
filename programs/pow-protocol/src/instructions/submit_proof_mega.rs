// =============================================================================
// INSTRUCTION: SUBMIT PROOF MEGA
// =============================================================================
// Soumet une preuve mega ou super-mega sur la pool seeker uniquement.
//
// Différences avec submit_proof normal :
//   - Vérifie le hash contre la diff figée stockée dans MegaState (pas la diff seeker dynamique)
//   - Reward × MEGA_REWARD_MULT ou × SUPER_MEGA_REWARD_MULT
//   - Fee × MEGA_FEE_MULT ou × SUPER_MEGA_FEE_MULT (sur la base seeker)
//   - blocks_mined += FACTOR (1000 ou 10000) → decay reward cohérent
//   - NE PAS push dans block_timestamps → préserve l'algo de difficulté
//   - Force-trigger le cycle gate (1 buyback bonus)
//   - Re-snapshot la diff résolue après mint

use anchor_lang::prelude::*;
use solana_program::hash::hash;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{
    BlockLevel, CycleGate, DeviceAttestation, MegaState, MintAuthority, MinerStats, PowConfig,
};
use crate::instructions::submit_proof::{
    calculate_current_fee, calculate_reward, generate_new_challenge,
};

pub fn handler(ctx: Context<SubmitProofMega>, nonce: u128, level: BlockLevel) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;

    // ==========================================================================
    // VÉRIFICATIONS INITIALES
    // ==========================================================================

    require!(ctx.accounts.pow_config.is_initialized, PowError::NotInitialized);
    require!(!ctx.accounts.pow_config.is_paused, PowError::ProtocolPaused);
    require!(
        ctx.accounts.pow_config.pool_id == POOL_SEEKER,
        PowError::MegaOnSeekerOnly
    );

    let mega_state_difficulty = match level {
        BlockLevel::Mega => ctx.accounts.mega_state.mega_difficulty,
        BlockLevel::SuperMega => ctx.accounts.mega_state.super_mega_difficulty,
    };
    require!(mega_state_difficulty > 0, PowError::MegaNotInitialized);

    // Combined supply check across both pools
    let combined_supply = ctx.accounts.pow_config.total_supply_mined
        .checked_add(ctx.accounts.other_pool.total_supply_mined)
        .ok_or(PowError::Overflow)?;
    require!(combined_supply < MAX_SUPPLY, PowError::MaxSupplyReached);

    let combined_emitted: u128 = {
        let this = &ctx.accounts.pow_config;
        let other = &ctx.accounts.other_pool;
        (this.total_supply_mined as u128)
            .saturating_add(this.total_burned_from_buyback as u128)
            .saturating_add(this.total_burned_from_transfer_tax as u128)
            .saturating_add(other.total_supply_mined as u128)
            .saturating_add(other.total_burned_from_buyback as u128)
            .saturating_add(other.total_burned_from_transfer_tax as u128)
    };

    // ==========================================================================
    // VÉRIFIER L'ATTESTATION DEVICE (seeker uniquement → toujours requis ici)
    // ==========================================================================

    let attestation = ctx.accounts.attestation.as_mut()
        .ok_or(PowError::AttestationRequired)?;
    require!(!attestation.is_used, PowError::AttestationAlreadyUsed);
    require!(
        now - attestation.timestamp <= ATTESTATION_VALIDITY_SECS,
        PowError::AttestationExpired
    );
    require!(
        attestation.authority == ctx.accounts.pow_config.attestation_authority,
        PowError::InvalidAttestationAuthority
    );
    attestation.is_used = true;
    msg!("Device attestation consumed (age: {}s)", now - attestation.timestamp);

    // ==========================================================================
    // VÉRIFIER LA PREUVE CONTRE LA DIFF MEGA FIGÉE
    // ==========================================================================

    let config = &ctx.accounts.pow_config;
    let is_valid = verify_mega_proof(
        &config.current_challenge,
        ctx.accounts.miner.key().as_ref(),
        nonce,
        config.blocks_mined,
        mega_state_difficulty,
    )?;
    require!(is_valid, PowError::InvalidMegaProof);

    // ==========================================================================
    // CALCULER LA FEE (×MULT sur la base seeker du moment)
    // ==========================================================================

    let base_fee = calculate_current_fee(combined_emitted)?;
    let fee_mult: u64 = match level {
        BlockLevel::Mega => MEGA_FEE_MULT,
        BlockLevel::SuperMega => SUPER_MEGA_FEE_MULT,
    };
    let fee_sol = (base_fee as u128)
        .checked_mul(fee_mult as u128)
        .ok_or(PowError::Overflow)?
        .min(u64::MAX as u128) as u64;

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

    let config = &mut ctx.accounts.pow_config;
    config.total_fees_collected = config.total_fees_collected
        .checked_add(fee_sol)
        .ok_or(PowError::Overflow)?;
    config.fee_sol_current = fee_sol;

    // ==========================================================================
    // CALCULER LE REWARD (× MULT sur le base reward)
    // ==========================================================================

    let base_reward = calculate_reward(config.blocks_mined, config.launch_ts, now)?;
    let reward_mult: u64 = match level {
        BlockLevel::Mega => MEGA_REWARD_MULT,
        BlockLevel::SuperMega => SUPER_MEGA_REWARD_MULT,
    };
    let mega_reward = (base_reward as u128)
        .checked_mul(reward_mult as u128)
        .ok_or(PowError::Overflow)?
        .min(u64::MAX as u128) as u64;

    let total_reward = mega_reward
        .checked_add(config.pending_reward_tokens)
        .ok_or(PowError::Overflow)?;

    let actual_reward = if combined_supply + total_reward > MAX_SUPPLY {
        MAX_SUPPLY - combined_supply
    } else {
        total_reward
    };

    config.pending_reward_tokens = 0;

    // ==========================================================================
    // MINT LES TOKENS AU MINEUR
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
    // INCRÉMENTER blocks_mined PAR FACTOR (decay cohérent)
    // NE PAS push dans block_timestamps (préserve l'algo de difficulté)
    // ==========================================================================

    let block_increment: u64 = match level {
        BlockLevel::Mega => MEGA_FACTOR as u64,
        BlockLevel::SuperMega => SUPER_MEGA_FACTOR as u64,
    };

    let config = &mut ctx.accounts.pow_config;
    config.blocks_mined = config.blocks_mined
        .checked_add(block_increment)
        .ok_or(PowError::Overflow)?;
    config.last_block_ts = now;

    // Nouveau challenge (comme un block normal)
    config.current_challenge = generate_new_challenge(
        &config.current_challenge,
        nonce,
        clock.slot,
        config.blocks_mined,
    );

    // ==========================================================================
    // RE-SNAPSHOT LA DIFF MEGA RÉSOLUE (= seeker_diff actuelle × FACTOR)
    // ==========================================================================

    let seeker_diff = ctx.accounts.pow_config.difficulty;
    let mega_state = &mut ctx.accounts.mega_state;
    match level {
        BlockLevel::Mega => {
            mega_state.mega_difficulty = seeker_diff
                .checked_mul(MEGA_FACTOR)
                .ok_or(PowError::Overflow)?;
            mega_state.mega_count = mega_state.mega_count
                .checked_add(1)
                .ok_or(PowError::Overflow)?;
            mega_state.last_mega_ts = now;
        }
        BlockLevel::SuperMega => {
            mega_state.super_mega_difficulty = seeker_diff
                .checked_mul(SUPER_MEGA_FACTOR)
                .ok_or(PowError::Overflow)?;
            mega_state.super_mega_count = mega_state.super_mega_count
                .checked_add(1)
                .ok_or(PowError::Overflow)?;
            mega_state.last_super_mega_ts = now;
        }
    }

    // ==========================================================================
    // STATS DU MINEUR
    // ==========================================================================

    let miner_stats = &mut ctx.accounts.miner_stats;
    if miner_stats.blocks_mined == 0 {
        miner_stats.miner = ctx.accounts.miner.key();
        miner_stats.first_block_ts = now;
        miner_stats.bump = ctx.bumps.miner_stats;
        miner_stats.pool_id = POOL_SEEKER;
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
    // FORCE-TRIGGER CYCLE GATE (1 buyback bonus)
    // ==========================================================================

    let cycle_number = ctx.accounts.pow_config.blocks_mined / BLOCKS_PER_CYCLE;
    let block_number = ctx.accounts.pow_config.blocks_mined;

    let cycle_gate_info = &ctx.accounts.cycle_gate;
    if cycle_gate_info.data_len() == 0 {
        let space = CycleGate::LEN;
        let lamports = Rent::get()?.minimum_balance(space);
        let cg_bump = ctx.bumps.cycle_gate;
        let seeds: &[&[u8]] = &[CYCLE_GATE_SEED, &[cg_bump]];
        anchor_lang::system_program::create_account(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.miner.to_account_info(),
                    to: cycle_gate_info.to_account_info(),
                },
                &[seeds],
            ),
            lamports,
            space as u64,
            ctx.program_id,
        )?;
    }

    let gate = CycleGate {
        cycle_number,
        block_number,
        timestamp: now,
        is_consumed: false,
        bump: ctx.bumps.cycle_gate,
    };
    let mut data = ctx.accounts.cycle_gate.try_borrow_mut_data()?;
    gate.try_serialize(&mut (&mut data[..] as &mut [u8]))?;

    // ==========================================================================
    // EVENTS + LOGS
    // ==========================================================================

    match level {
        BlockLevel::Mega => {
            msg!("MEGA BLOCK MINED!");
            emit!(MegaBlockMined {
                miner: ctx.accounts.miner.key(),
                reward: actual_reward,
                fee_sol,
                mega_count: ctx.accounts.mega_state.mega_count,
                block_number,
                timestamp: now,
            });
        }
        BlockLevel::SuperMega => {
            msg!("SUPER MEGA BLOCK MINED!");
            emit!(SuperMegaBlockMined {
                miner: ctx.accounts.miner.key(),
                reward: actual_reward,
                fee_sol,
                super_mega_count: ctx.accounts.mega_state.super_mega_count,
                block_number,
                timestamp: now,
            });
        }
    }

    msg!("Reward: {} tokens", actual_reward);
    msg!("Fee paid: {} lamports", fee_sol);
    msg!("blocks_mined: {} (+{})", block_number, block_increment);
    msg!("CycleGate force-triggered: cycle #{}, block #{}", cycle_number, block_number);

    Ok(())
}

/// Vérifie un hash contre une difficulté arbitraire (mega ou super-mega).
/// Identique à verify_proof normal mais paramétrée sur une diff externe.
fn verify_mega_proof(
    challenge: &[u8; 32],
    miner_pubkey: &[u8],
    nonce: u128,
    blocks_mined: u64,
    difficulty: u128,
) -> Result<bool> {
    require!(difficulty > 0, PowError::InvalidDifficulty);

    let mut message = Vec::with_capacity(88);
    message.extend_from_slice(challenge);
    message.extend_from_slice(miner_pubkey);
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&blocks_mined.to_le_bytes());

    let hash_result = hash(&message);
    let hash_bytes = hash_result.to_bytes();
    let hash_value = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());
    let target = u128::MAX / difficulty;

    msg!("Mega verify: hash_value={}, target={}, valid={}", hash_value, target, hash_value < target);

    Ok(hash_value < target)
}

// =============================================================================
// EVENTS
// =============================================================================

#[event]
pub struct MegaBlockMined {
    pub miner: Pubkey,
    pub reward: u64,
    pub fee_sol: u64,
    pub mega_count: u64,
    pub block_number: u64,
    pub timestamp: i64,
}

#[event]
pub struct SuperMegaBlockMined {
    pub miner: Pubkey,
    pub reward: u64,
    pub fee_sol: u64,
    pub super_mega_count: u64,
    pub block_number: u64,
    pub timestamp: i64,
}

// =============================================================================
// CONTEXTE DE L'INSTRUCTION
// =============================================================================

#[derive(Accounts)]
pub struct SubmitProofMega<'info> {
    #[account(mut)]
    pub miner: Signer<'info>,

    /// Pool seeker (writable)
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[POOL_SEEKER]],
        bump = pow_config.bump,
        has_one = mint @ PowError::InvalidMint,
    )]
    pub pow_config: Box<Account<'info, PowConfig>>,

    /// Pool normale (read-only, pour le supply cap combiné)
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = other_pool.bump,
        constraint = other_pool.pool_id == POOL_NORMAL @ PowError::InvalidPoolId,
    )]
    pub other_pool: Box<Account<'info, PowConfig>>,

    /// MegaState PDA (writable, re-snapshot après mega/super)
    #[account(
        mut,
        seeds = [MEGA_STATE_SEED],
        bump = mega_state.bump,
    )]
    pub mega_state: Box<Account<'info, MegaState>>,

    #[account(
        seeds = [MINT_AUTHORITY_SEED],
        bump = mint_authority.bump,
    )]
    pub mint_authority: Account<'info, MintAuthority>,

    #[account(
        mut,
        mint::token_program = token_program,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = miner,
        token::token_program = token_program,
    )]
    pub miner_token_account: InterfaceAccount<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = miner,
        space = MinerStats::LEN,
        seeds = [MINER_STATS_SEED, &[POOL_SEEKER], miner.key().as_ref()],
        bump,
    )]
    pub miner_stats: Account<'info, MinerStats>,

    /// CHECK: PDA vérifié par seeds
    #[account(
        mut,
        seeds = [FEE_VAULT_SEED],
        bump,
    )]
    pub fee_collector: AccountInfo<'info>,

    /// Attestation device (toujours requise — seeker uniquement)
    #[account(
        mut,
        seeds = [DEVICE_ATTEST_SEED, miner.key().as_ref()],
        bump,
    )]
    pub attestation: Option<Account<'info, DeviceAttestation>>,

    /// CycleGate PDA (force-trigger sur mega)
    /// CHECK: serialized manuellement
    #[account(
        mut,
        seeds = [CYCLE_GATE_SEED],
        bump,
    )]
    pub cycle_gate: AccountInfo<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,
}
