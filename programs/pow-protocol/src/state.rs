// =============================================================================
// STRUCTURES DE DONNÉES DU PROTOCOLE POW
// =============================================================================

use anchor_lang::prelude::*;

// =============================================================================
// POW CONFIG - Configuration principale du protocole
// =============================================================================

/// Configuration principale du protocole PoW
/// Stocke tous les paramètres et l'état global
#[account]
#[derive(Default)]
pub struct PowConfig {
    /// Autorité du protocole (peut mettre à jour les paramètres)
    pub authority: Pubkey,
    
    /// Adresse du mint SPL2022
    pub mint: Pubkey,

    // =========================================================================
    // ÉTAT DU MINING
    // =========================================================================
    
    /// Difficulté actuelle (plus c'est grand, plus c'est difficile)
    pub difficulty: u128,
    
    /// Timestamp du dernier bloc miné
    pub last_block_ts: i64,
    
    /// Nombre total de blocs minés
    pub blocks_mined: u64,
    
    /// Supply totale minée (en base décimales)
    pub total_supply_mined: u64,
    
    /// Challenge actuel (seed pour le PoW)
    pub current_challenge: [u8; 32],

    // =========================================================================
    // REWARDS
    // =========================================================================
    
    /// Pending reward tokens (venant de la taxe transfert SPL2022)
    pub pending_reward_tokens: u64,

    // =========================================================================
    // FEES
    // =========================================================================
    
    /// Fee SOL actuelle (en lamports)
    pub fee_sol_current: u64,
    
    /// Total des fees SOL collectées depuis le début
    pub total_fees_collected: u64,
    
    /// Total SOL envoyé à la team
    pub total_team_fees: u64,
    
    /// Total SOL utilisé pour buyback
    pub total_buyback_sol: u64,
    
    /// Total SOL ajouté à la LP
    pub total_lp_sol: u64,

    // =========================================================================
    // BURNS
    // =========================================================================
    
    /// Total de tokens brûlés (via buyback)
    pub total_burned_from_buyback: u64,
    
    /// Total de tokens brûlés (via taxe transfert)
    pub total_burned_from_transfer_tax: u64,

    // =========================================================================
    // TIMESTAMPS
    // =========================================================================
    
    /// Timestamp du lancement du protocole
    pub launch_ts: i64,
    
    /// Timestamp de la dernière mise à jour de fee
    pub last_fee_update_ts: i64,

    // =========================================================================
    // FLAGS & BUMPS
    // =========================================================================
    
    /// Est-ce que le protocole est initialisé
    pub is_initialized: bool,
    
    /// Est-ce que le protocole est en pause
    pub is_paused: bool,
    
    /// Bump du PDA
    pub bump: u8,

    // =========================================================================
    // DIFFICULTY ADJUSTMENT (Moving Average)
    // =========================================================================

    /// Circular buffer of last N block timestamps for moving average
    /// Used to smooth difficulty adjustments and reduce volatility
    pub block_timestamps: [i64; 10],

    /// Current index in the circular buffer (0-9)
    pub block_timestamps_index: u8,

    /// Number of timestamps stored (0-10, used during initial fill)
    pub block_timestamps_count: u8,

    /// Backend pubkey autorisée à créer des attestations device
    /// Si Pubkey::default() (all zeros), attestation is disabled
    pub attestation_authority: Pubkey,

    /// Pool ID: 0 = normal (open), 1 = seeker (requires TEE attestation)
    pub pool_id: u8,
}

/// Number of blocks to use for difficulty moving average
pub const DIFFICULTY_WINDOW_SIZE: usize = 10;

impl PowConfig {
    /// Taille du compte en bytes
    pub const LEN: usize = 8 +  // discriminator
        32 +    // authority
        32 +    // mint
        16 +    // difficulty (u128)
        8 +     // last_block_ts
        8 +     // blocks_mined
        8 +     // total_supply_mined
        32 +    // current_challenge
        8 +     // pending_reward_tokens
        8 +     // fee_sol_current
        8 +     // total_fees_collected
        8 +     // total_team_fees
        8 +     // total_buyback_sol
        8 +     // total_lp_sol
        8 +     // total_burned_from_buyback
        8 +     // total_burned_from_transfer_tax
        8 +     // launch_ts
        8 +     // last_fee_update_ts
        1 +     // is_initialized
        1 +     // is_paused
        1 +     // bump
        (8 * 10) +  // block_timestamps (10 x i64)
        1 +     // block_timestamps_index
        1 +     // block_timestamps_count
        32 +    // attestation_authority
        1;      // pool_id
}

// =============================================================================
// MINER STATS - Statistiques par mineur
// =============================================================================

/// Statistiques d'un mineur individuel
#[account]
#[derive(Default)]
pub struct MinerStats {
    /// Adresse du mineur
    pub miner: Pubkey,
    
    /// Nombre de blocs minés par ce mineur
    pub blocks_mined: u64,
    
    /// Total de tokens gagnés
    pub total_tokens_earned: u64,
    
    /// Total de fees SOL payées
    pub total_fees_paid: u64,
    
    /// Timestamp du premier bloc miné
    pub first_block_ts: i64,
    
    /// Timestamp du dernier bloc miné
    pub last_block_ts: i64,

    /// Bump du PDA
    pub bump: u8,

    /// Pool ID (0 = normal, 1 = seeker)
    pub pool_id: u8,
}

impl MinerStats {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // miner
        8 +     // blocks_mined
        8 +     // total_tokens_earned
        8 +     // total_fees_paid
        8 +     // first_block_ts
        8 +     // last_block_ts
        1 +     // bump
        1;      // pool_id
}

// =============================================================================
// PENDING PROOF - Preuve en attente de validation
// =============================================================================

/// Structure pour une preuve soumise (optionnelle, pour système de queue)
#[account]
#[derive(Default)]
pub struct PendingProof {
    /// Adresse du mineur
    pub miner: Pubkey,
    
    /// Nonce trouvé
    pub nonce: u64,
    
    /// Challenge utilisé
    pub challenge: [u8; 32],
    
    /// Timestamp de soumission
    pub submitted_at: i64,
    
    /// Est-ce que la preuve a été validée
    pub is_validated: bool,
    
    /// Bump du PDA
    pub bump: u8,
}

impl PendingProof {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // miner
        8 +     // nonce
        32 +    // challenge
        8 +     // submitted_at
        1 +     // is_validated
        1;      // bump
}

// =============================================================================
// FEE DISTRIBUTION RECORD - Historique des distributions
// =============================================================================

/// Record d'une distribution de fees (pour audit/tracking)
#[account]
#[derive(Default)]
pub struct FeeDistributionRecord {
    /// Index de la distribution
    pub index: u64,
    
    /// Timestamp de la distribution
    pub timestamp: i64,
    
    /// Total SOL distribué
    pub total_sol: u64,
    
    /// SOL envoyé à la team
    pub team_sol: u64,
    
    /// SOL utilisé pour buyback
    pub buyback_sol: u64,
    
    /// SOL ajouté à la LP
    pub lp_sol: u64,
    
    /// Tokens brûlés lors de cette distribution
    pub tokens_burned: u64,
    
    /// Tokens ajoutés à la LP
    pub tokens_to_lp: u64,
    
    /// Bump du PDA
    pub bump: u8,
}

impl FeeDistributionRecord {
    pub const LEN: usize = 8 +  // discriminator
        8 +     // index
        8 +     // timestamp
        8 +     // total_sol
        8 +     // team_sol
        8 +     // buyback_sol
        8 +     // lp_sol
        8 +     // tokens_burned
        8 +     // tokens_to_lp
        1;      // bump
}

// =============================================================================
// HALVING INFO - Information sur les halvings
// =============================================================================

/// Informations sur l'état du halving (pour dashboard/UI)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default)]
pub struct HalvingInfo {
    /// Numéro du halving actuel (0 = avant premier halving)
    pub current_halving: u8,
    
    /// Blocs restants avant prochain halving
    pub blocks_until_next: u64,
    
    /// Reward actuel par bloc
    pub current_reward: u64,
    
    /// Reward après prochain halving
    pub next_reward: u64,
}

// =============================================================================
// PROTOCOL STATS - Stats globales pour dashboard
// =============================================================================

// =============================================================================
// DEVICE ATTESTATION - Attestation hardware par le backend
// =============================================================================

/// Attestation de device créée par le backend après vérification TEE.
/// Valide pendant 60 secondes on-chain.
/// Consommée après chaque submit_proof (is_used = true).
/// Le mineur doit re-attester avant de soumettre un nouveau bloc.
#[account]
pub struct DeviceAttestation {
    /// Adresse du mineur attesté
    pub miner: Pubkey,
    /// Authority backend qui a signé l'attestation
    pub authority: Pubkey,
    /// Unix timestamp de création/refresh
    pub timestamp: i64,
    /// Bump du PDA
    pub bump: u8,
    /// Whether this attestation has been consumed by a submit_proof
    pub is_used: bool,
}

impl DeviceAttestation {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // miner
        32 +    // authority
        8 +     // timestamp
        1 +     // bump
        1;      // is_used
}

// =============================================================================
// MINT AUTHORITY - Shared authority for minting across both pools
// =============================================================================

/// Shared mint authority PDA. Both pools use this to sign mint_to CPI calls.
/// PDA seeds: [b"pow_mint_auth"]
#[account]
pub struct MintAuthority {
    pub bump: u8,
}

impl MintAuthority {
    pub const LEN: usize = 8 + 1; // discriminator + bump
}

// =============================================================================
// PROTOCOL STATS - Stats globales pour dashboard
// =============================================================================

/// Statistiques globales du protocole (vue read-only)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Default)]
pub struct ProtocolStats {
    /// Supply totale minée
    pub total_mined: u64,
    
    /// Supply restante à miner
    pub remaining_supply: u64,
    
    /// Pourcentage miné (basis points, ex: 500 = 5%)
    pub percent_mined: u16,
    
    /// Nombre total de blocs
    pub total_blocks: u64,
    
    /// Difficulté actuelle
    pub current_difficulty: u128,
    
    /// Fee SOL actuelle
    pub current_fee_sol: u64,
    
    /// Pending reward pour prochain bloc
    pub pending_reward: u64,
    
    /// Hashrate estimé (blocs par heure)
    pub estimated_hashrate: u64,
    
    /// Info halving
    pub halving_info: HalvingInfo,
}
