// =============================================================================
// INSTRUCTION: SUBMIT PROOF
// =============================================================================
// Le cœur du système PoW - Soumet une preuve de travail valide

use anchor_lang::prelude::*;
use solana_program::hash::hash;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{PowConfig, MinerStats};

/// Soumet une preuve de travail (PoW)
///
/// Le mineur doit trouver un nonce tel que:
/// hash(challenge || nonce) < target (basé sur difficulty)
///
/// Si la preuve est valide:
/// 1. Le mineur paie la fee en SOL
/// 2. Le mineur reçoit le reward (base + pending)
/// 3. La difficulté est ajustée
/// 4. Un nouveau challenge est généré
pub fn handler(ctx: Context<SubmitProof>, nonce: u128) -> Result<()> {
    let clock = Clock::get()?;
    let now = clock.unix_timestamp;

    // ==========================================================================
    // VÉRIFICATIONS INITIALES
    // ==========================================================================

    require!(ctx.accounts.pow_config.is_initialized, PowError::NotInitialized);
    require!(!ctx.accounts.pow_config.is_paused, PowError::ProtocolPaused);
    require!(ctx.accounts.pow_config.total_supply_mined < MAX_SUPPLY, PowError::MaxSupplyReached);

    let config = &mut ctx.accounts.pow_config;

    // ==========================================================================
    // VÉRIFIER LA PREUVE (PoW)
    // ==========================================================================

    let is_valid = verify_proof(
        &config.current_challenge,
        ctx.accounts.miner.key().as_ref(), // Adresse du mineur pour anti-pool-theft
        nonce,
        config.blocks_mined, // Utiliser blocks_mined comme block_number
        config.difficulty,
    )?;

    require!(is_valid, PowError::InvalidProof);

    // ==========================================================================
    // CALCULER ET COLLECTER LA FEE SOL
    // ==========================================================================
    
    let fee_sol = calculate_current_fee(config.launch_ts, now)?;
    
    // Transférer la fee du mineur vers le programme
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

    // Mettre à jour le tracking des fees
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
    
    // Total reward = base + pending (de la taxe transfert)
    let total_reward = base_reward
        .checked_add(config.pending_reward_tokens)
        .ok_or(PowError::Overflow)?;
    
    // Vérifier qu'on ne dépasse pas le max supply
    let actual_reward = if config.total_supply_mined + total_reward > MAX_SUPPLY {
        MAX_SUPPLY - config.total_supply_mined
    } else {
        total_reward
    };

    // Reset le pending reward
    config.pending_reward_tokens = 0;

    // ==========================================================================
    // MINT LES TOKENS AU MINEUR
    // ==========================================================================

    if actual_reward > 0 {
        // Sauvegarder le bump et les valeurs avant de libérer le borrow
        let config_bump = config.bump;
        let new_total_supply = config.total_supply_mined
            .checked_add(actual_reward)
            .ok_or(PowError::Overflow)?;

        // Libérer le borrow mutable

        // Faire le mint
        let signer_seeds: &[&[&[u8]]] = &[&[
            POW_CONFIG_SEED,
            &[config_bump],
        ]];

        anchor_spl::token_interface::mint_to(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token_interface::MintTo {
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.miner_token_account.to_account_info(),
                    authority: ctx.accounts.pow_config.to_account_info(),
                },
                signer_seeds,
            ),
            actual_reward,
        )?;

        // Re-emprunter et mettre à jour
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
    // AJUSTER LA DIFFICULTÉ (basé sur la moyenne des derniers blocs)
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

    // Générer un nouveau challenge
    ctx.accounts.pow_config.current_challenge = generate_new_challenge(
        &ctx.accounts.pow_config.current_challenge,
        nonce,
        clock.slot,
        ctx.accounts.pow_config.blocks_mined, // Numéro de bloc pour unicité absolue
    );

    // ==========================================================================
    // METTRE À JOUR LES STATS DU MINEUR
    // ==========================================================================

    let miner_stats = &mut ctx.accounts.miner_stats;

    if miner_stats.blocks_mined == 0 {
        miner_stats.miner = ctx.accounts.miner.key();
        miner_stats.first_block_ts = now;
        miner_stats.bump = ctx.bumps.miner_stats;
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

    msg!("Block #{} mined!", ctx.accounts.pow_config.blocks_mined);
    msg!("Miner: {}", ctx.accounts.miner.key());
    msg!("Reward: {} tokens", actual_reward);
    msg!("Fee paid: {} lamports", fee_sol);
    msg!("New difficulty: {}", ctx.accounts.pow_config.difficulty);
    msg!("Total supply mined: {}", ctx.accounts.pow_config.total_supply_mined);

    Ok(())
}

// =============================================================================
// FONCTIONS UTILITAIRES
// =============================================================================

/// Vérifie si la preuve est valide
/// hash(challenge || miner_pubkey || nonce || block_number) doit être < target
/// L'inclusion de miner_pubkey empêche le vol de travail dans les pools
fn verify_proof(challenge: &[u8; 32], miner_pubkey: &[u8], nonce: u128, blocks_mined: u64, difficulty: u128) -> Result<bool> {
    // Construire le message à hasher: challenge (32) + miner (32) + nonce (16) + block_number (8) = 88 bytes
    let mut message = Vec::with_capacity(88);
    message.extend_from_slice(challenge);
    message.extend_from_slice(miner_pubkey); // 32 bytes - Adresse du mineur
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&blocks_mined.to_le_bytes());

    msg!("DEBUG verify_proof:");
    msg!("  Challenge: {:?}", &challenge[..8]);
    msg!("  Miner: {:?}", &miner_pubkey[..8]);
    msg!("  Nonce: {}", nonce);
    msg!("  Blocks mined: {}", blocks_mined);
    msg!("  Message len: {}", message.len());

    // Calculer le hash SHA256
    let hash_result = hash(&message);
    let hash_bytes = hash_result.to_bytes();

    msg!("  Hash (first 16): {:?}", &hash_bytes[..16]);

    // Convertir les premiers 16 bytes en u128 pour comparaison
    let hash_value = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());

    // Le target est inversé : plus difficulty est grand, plus target est petit
    // target = MAX_U128 / difficulty
    let target = u128::MAX / difficulty;

    msg!("  Hash value: {}", hash_value);
    msg!("  Target: {}", target);
    msg!("  Valid: {}", hash_value < target);

    Ok(hash_value < target)
}

/// Calcule le reward pour un bloc donné
/// Utilise une décroissance exponentielle avec DECAY_FACTOR = 0.999999943 par bloc
///
/// Formule: reward = base_reward * DECAY_FACTOR^blocks_mined
///
/// Pour éviter les floats, on utilise des calculs en u128 avec précision:
/// - DECAY_FACTOR_NUMERATOR = 999_999_943
/// - DECAY_FACTOR_DENOMINATOR = 1_000_000_000
///
/// Décroissance annuelle: ~2.95% (demi-vie ~23 ans)
fn calculate_reward(blocks_mined: u64, launch_ts: i64, now: i64) -> Result<u64> {
    let elapsed = now - launch_ts;

    // Déterminer si on est dans la période de boost (1ère année)
    let base_reward = if elapsed < BOOST_DURATION {
        R0_BOOST
    } else {
        R0_NORMAL
    };

    // Appliquer la décroissance exponentielle: reward = base_reward * (k^blocks_mined)
    // Pour éviter les calculs bloc par bloc (trop coûteux), on utilise une approximation
    // par groupes de blocs avec précision u128.
    //
    // Approche: Calculer le decay factor agrégé par groupes de 1000 blocs
    // decay_1000 = 0.999999943^1000 ≈ 0.999943 = 999943 / 1000000
    //
    // Puis appliquer bloc par bloc pour le reste

    let full_groups = blocks_mined / 1000;
    let remaining_blocks = blocks_mined % 1000;

    // Decay factor pour 1000 blocs: 0.999999943^1000 ≈ 0.99994300204
    // Arrondi à 999943 / 1000000 pour éviter l'accumulation d'erreurs
    const DECAY_1000_NUM: u128 = 999943;
    const DECAY_1000_DEN: u128 = 1000000;

    let mut reward = base_reward as u128;

    // Appliquer le decay par groupes de 1000 blocs
    // On limite à 10000 groupes (10M blocs ≈ 19 ans) pour éviter les boucles trop longues
    for _ in 0..full_groups.min(10000) {
        reward = reward
            .checked_mul(DECAY_1000_NUM)
            .ok_or(PowError::Overflow)?
            .checked_div(DECAY_1000_DEN)
            .ok_or(PowError::DivisionByZero)?;

        // Early exit si le reward devient trop petit
        if reward < 1000 {
            break;
        }
    }

    // Appliquer le decay pour les blocs restants (0-999)
    // On utilise le decay factor exact par groupes de 100 blocs
    // decay_100 = 0.999999943^100 ≈ 0.999994300
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

    // Pour les derniers blocs (0-99), appliquer bloc par bloc
    for _ in 0..final_blocks {
        reward = reward
            .checked_mul(DECAY_FACTOR_NUMERATOR)
            .ok_or(PowError::Overflow)?
            .checked_div(DECAY_FACTOR_DENOMINATOR)
            .ok_or(PowError::DivisionByZero)?;
    }

    // Convertir en u64, minimum 1 pour éviter 0
    let final_reward = (reward as u64).max(1);

    // Minimum reward de 0.001 token pour éviter des rewards négligeables
    let min_reward = DECIMALS_MULTIPLIER / 1000; // 0.001 token = 1_000_000

    Ok(final_reward.max(min_reward))
}

/// Calcule la fee SOL actuelle basée sur le temps écoulé
/// Fee augmente de 1.5x tous les 2 ans, cap à 0.05 SOL
fn calculate_current_fee(launch_ts: i64, now: i64) -> Result<u64> {
    let elapsed = now - launch_ts;
    let two_years_in_seconds = 2 * SECONDS_PER_YEAR;
    
    // Nombre de périodes de 2 ans écoulées
    let periods = (elapsed / two_years_in_seconds) as u32;
    
    let mut fee = FEE_INITIAL_SOL;
    
    for _ in 0..periods.min(10) { // Max 10 périodes (20 ans)
        // Multiplier par 1.5 : fee = fee * 150 / 100
        fee = fee
            .checked_mul(FEE_MULTIPLIER_NUMERATOR)
            .ok_or(PowError::Overflow)?
            .checked_div(FEE_MULTIPLIER_DENOMINATOR)
            .ok_or(PowError::DivisionByZero)?;
        
        // Appliquer le cap
        if fee > FEE_SOL_CAP {
            fee = FEE_SOL_CAP;
            break;
        }
    }
    
    Ok(fee)
}

/// Ajuste la difficulté en fonction du temps moyen entre les blocs (moving average)
///
/// Cette fonction utilise une moyenne mobile des N derniers blocs pour lisser
/// les ajustements et éviter la volatilité excessive.
///
/// Arguments:
/// - current_difficulty: Difficulté actuelle
/// - block_timestamps: Buffer circulaire des timestamps des derniers blocs
/// - timestamps_count: Nombre de timestamps stockés (0 à WINDOW_SIZE)
/// - current_ts: Timestamp du bloc actuel
///
/// Exemples avec moyenne sur 10 blocs (target 60s = 600s pour 10 blocs):
/// - Moyenne 30s/bloc → ratio 0.5 → augmenter significativement
/// - Moyenne 60s/bloc → ratio 1.0 → pas de changement
/// - Moyenne 120s/bloc → ratio 2.0 → diminuer significativement
fn adjust_difficulty_with_average(
    current_difficulty: u128,
    block_timestamps: &[i64; 10],
    timestamps_count: u8,
    current_ts: i64,
) -> Result<u128> {
    // Si on n'a pas assez d'historique, utiliser un ajustement léger basé sur le dernier bloc
    if timestamps_count < 2 {
        return Ok(current_difficulty);
    }

    // Calculer le temps total sur la fenêtre
    // On prend le plus ancien timestamp disponible
    let count = timestamps_count as usize;

    // Trouver le timestamp le plus ancien dans le buffer
    // Les timestamps sont stockés de façon circulaire
    let oldest_ts = block_timestamps.iter()
        .take(count)
        .copied()
        .filter(|&ts| ts > 0)
        .min()
        .unwrap_or(current_ts);

    // Temps total écoulé depuis le plus ancien bloc
    let total_time = current_ts.saturating_sub(oldest_ts);

    // Nombre d'intervalles = nombre de blocs - 1
    let intervals = count.saturating_sub(1) as i64;
    if intervals <= 0 {
        return Ok(current_difficulty);
    }

    // Temps moyen par bloc
    let avg_block_time = total_time / intervals;

    msg!("Difficulty adjustment: {} blocks, {}s total, {}s avg (target: {}s)",
        count, total_time, avg_block_time, TARGET_BLOCK_TIME);

    // Calculer le ratio temps_moyen / temps_cible (en millièmes pour précision)
    let avg_u128 = avg_block_time.max(1) as u128;
    let target_u128 = TARGET_BLOCK_TIME as u128;

    let ratio_x1000 = avg_u128
        .checked_mul(1000)
        .ok_or(PowError::Overflow)?
        .checked_div(target_u128)
        .ok_or(PowError::DivisionByZero)?;

    // Déterminer le facteur d'ajustement selon les paliers
    // Les paliers sont plus larges car on utilise une moyenne (plus stable)
    let (adjustment_num, adjustment_den): (u128, u128) = if ratio_x1000 < 500 {
        // ratio < 0.5 : Blocs très rapides (< 30s avg) → +50%
        (3, 2)
    } else if ratio_x1000 < 750 {
        // ratio < 0.75 : Blocs rapides (30-45s avg) → +25%
        (5, 4)
    } else if ratio_x1000 < 900 {
        // ratio < 0.9 : Blocs légèrement rapides (45-54s avg) → +10%
        (11, 10)
    } else if ratio_x1000 <= 1100 {
        // 0.9 <= ratio <= 1.1 : Dans la cible (54-66s avg) → pas de changement
        (1, 1)
    } else if ratio_x1000 <= 1333 {
        // ratio <= 1.33 : Blocs légèrement lents (66-80s avg) → -10%
        (9, 10)
    } else if ratio_x1000 <= 2000 {
        // ratio <= 2.0 : Blocs lents (80-120s avg) → -20%
        (4, 5)
    } else {
        // ratio > 2.0 : Blocs très lents (> 120s avg) → -33%
        (2, 3)
    };

    msg!("Ratio x1000: {}, adjustment: {}/{}", ratio_x1000, adjustment_num, adjustment_den);

    // Appliquer l'ajustement: new_diff = current_diff * (num / den)
    let new_difficulty = current_difficulty
        .checked_mul(adjustment_num)
        .ok_or(PowError::Overflow)?
        .checked_div(adjustment_den)
        .ok_or(PowError::DivisionByZero)?;

    // Appliquer les limites min/max
    Ok(new_difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY))
}

/// Génère un nouveau challenge basé sur l'ancien, le nonce, le slot et le numéro de bloc
///
/// Entrées:
/// - old_challenge: Hash du bloc précédent (chaîne de hash)
/// - nonce: Nonce gagnant du bloc précédent (entropie)
/// - slot: Slot Solana actuel (timestamp blockchain)
/// - block_number: Numéro de bloc (unicité absolue, résistance quantique)
///
/// Cette combinaison garantit:
/// 1. Unicité: Impossible d'avoir le même challenge deux fois
/// 2. Chaîne: Chaque bloc dépend du précédent (comme Bitcoin)
/// 3. Résistance aux collisions: Même si SHA256 a une collision, block_number diffère
fn generate_new_challenge(old_challenge: &[u8; 32], nonce: u128, slot: u64, block_number: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(old_challenge);           // 32 bytes - Hash précédent
    data.extend_from_slice(&nonce.to_le_bytes());    // 16 bytes - Nonce gagnant (u128)
    data.extend_from_slice(&slot.to_le_bytes());     // 8 bytes  - Slot Solana
    data.extend_from_slice(&block_number.to_le_bytes()); // 8 bytes  - Numéro de bloc

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

    /// Configuration du protocole
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED],
        bump = pow_config.bump,
        has_one = mint @ PowError::InvalidMint,
    )]
    pub pow_config: Account<'info, PowConfig>,

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

    /// Statistiques du mineur (PDA)
    #[account(
        init_if_needed,
        payer = miner,
        space = MinerStats::LEN,
        seeds = [MINER_STATS_SEED, miner.key().as_ref()],
        bump,
    )]
    pub miner_stats: Account<'info, MinerStats>,

    /// Compte qui collecte les fees (PDA du programme)
    /// CHECK: PDA vérifié par seeds
    #[account(
        mut,
        seeds = [FEE_VAULT_SEED],
        bump,
    )]
    pub fee_collector: AccountInfo<'info>,

    /// Programme Token
    pub token_program: Interface<'info, TokenInterface>,
    
    /// Programme System
    pub system_program: Program<'info, System>,
}
