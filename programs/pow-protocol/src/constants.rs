// =============================================================================
// CONSTANTES DU PROTOCOLE POW
// =============================================================================

// =============================================================================
// TOKEN PARAMETERS
// =============================================================================

/// Max supply: 1,000,000 tokens (avec 9 décimales)
pub const MAX_SUPPLY: u64 = 1_000_000 * DECIMALS_MULTIPLIER;

/// Decimales du token
pub const DECIMALS: u8 = 9;

/// Multiplicateur pour les décimales (10^9)
pub const DECIMALS_MULTIPLIER: u64 = 1_000_000_000;

// =============================================================================
// TIMING PARAMETERS
// =============================================================================

/// Target block time: 60 secondes
pub const TARGET_BLOCK_TIME: i64 = 60;

/// Secondes par an (approximatif)
pub const SECONDS_PER_YEAR: i64 = 365 * 24 * 60 * 60; // 31,536,000

// =============================================================================
// REWARD PARAMETERS (Émission exponentielle décroissante)
// =============================================================================

/// Reward initial normal (après 1ère année) - ~0.0287 tokens par bloc
/// Divisé par 2 car 2 pools = 2x blocs produits
pub const R0_NORMAL: u64 = 28_700_000;

/// Reward initial boosté (1ère année, x1.5) - ~0.0444 tokens par bloc
/// Divisé par 2 car 2 pools = 2x blocs produits
pub const R0_BOOST: u64 = 44_350_000;

/// Facteur de décroissance k (en millionièmes pour précision)
/// k ≈ 0.999999943 → stocké comme 999_999_943 / 1_000_000_000
pub const DECAY_FACTOR_NUMERATOR: u128 = 999_999_943;
pub const DECAY_FACTOR_DENOMINATOR: u128 = 1_000_000_000;

/// Durée du boost en secondes (1 an)
pub const BOOST_DURATION: i64 = SECONDS_PER_YEAR;

// =============================================================================
// FEE PARAMETERS (Fee géométrique basée sur l'émission cumulée)
// =============================================================================
//
// Formule: fee = FEE_INITIAL_SOL × 1000^(emitted / MAX_SUPPLY)
//   - 0% émis   →  0.001 SOL  (initiale)
//   - 50% émis  →  ~0.032 SOL
//   - 100% émis →  1.0 SOL    (cap atteint)
//
// `emitted` = total_supply_mined + total_burned_from_buyback + total_burned_from_transfer_tax
// (sommé sur les deux pools). C'est l'émission cumulée monotone — insensible aux burns.
//
// Calcul on-chain sans float via 4 paliers (max 36 itérations totales).
// Ratio exprimé en basis points (0..=10_000 pour 0..=100%).

/// Fee initiale: 0.001 SOL (en lamports) — utilisée à 0% d'émission
pub const FEE_INITIAL_SOL: u64 = 1_000_000;

/// Fee maximum: 1 SOL (en lamports) — atteinte à 100% d'émission
pub const FEE_SOL_CAP: u64 = 1_000_000_000;

/// Dénominateur commun pour tous les facteurs FEE_GEO_* (précision 10^12)
pub const FEE_GEO_DEN: u128 = 1_000_000_000_000;

/// 1000^(1/10) — facteur par palier de 10% d'émission (max 9 itérations)
pub const FEE_GEO_TEN_NUM: u128 = 1_995_262_314_969;

/// 1000^(1/100) — facteur par palier de 1% d'émission (max 9 itérations)
pub const FEE_GEO_ONE_NUM: u128 = 1_071_773_462_536;

/// 1000^(1/1000) — facteur par palier de 0.1% d'émission (max 9 itérations)
pub const FEE_GEO_TENTH_NUM: u128 = 1_006_931_668_873;

/// 1000^(1/10000) — facteur par palier de 0.01% d'émission (max 9 itérations)
pub const FEE_GEO_HUND_NUM: u128 = 1_000_691_134_091;

// =============================================================================
// FEE DISTRIBUTION (Split des fees SOL)
// =============================================================================

/// Team fee: 5%
pub const TEAM_FEE_PCT: u64 = 5;

// =============================================================================
// DIFFICULTY PARAMETERS
// =============================================================================

/// Difficulté initiale: 1M
pub const INITIAL_DIFFICULTY: u128 = 1_000_000;

/// Difficulté minimum (empêche de tomber à 0)
pub const MIN_DIFFICULTY: u128 = 1_000;

/// Difficulté maximum (empêche overflow)
pub const MAX_DIFFICULTY: u128 = u128::MAX / 1000;

// =============================================================================
// SEEDS FOR PDAs
// =============================================================================

pub const POW_CONFIG_SEED: &[u8] = b"pow_config";
pub const POW_VAULT_SEED: &[u8] = b"pow_vault";
pub const FEE_VAULT_SEED: &[u8] = b"fee_vault";
pub const TEAM_VAULT_SEED: &[u8] = b"team_vault";
pub const MINER_STATS_SEED: &[u8] = b"miner_stats";
pub const DEVICE_ATTEST_SEED: &[u8] = b"device_attest";
pub const MINT_AUTHORITY_SEED: &[u8] = b"pow_mint_auth";

// =============================================================================
// POOL PARAMETERS
// =============================================================================

/// Pool normale (ouverte à tous, pas d'attestation)
pub const POOL_NORMAL: u8 = 0;

/// Pool Seeker (requiert attestation TEE device)
pub const POOL_SEEKER: u8 = 1;

/// Durée de validité d'une attestation device (en secondes)
pub const ATTESTATION_VALIDITY_SECS: i64 = 60;

// =============================================================================
// TREASURY CYCLE PARAMETERS
// =============================================================================

/// Nombre de blocs par cycle treasury (buyback ou LP)
pub const BLOCKS_PER_CYCLE: u64 = 10;

/// Seed pour le cycle gate PDA
pub const CYCLE_GATE_SEED: &[u8] = b"cycle_gate";

/// Seed du treasury SOL vault PDA (dans pow-treasury)
pub const TREASURY_SOL_VAULT_SEED: &[u8] = b"treasury_sol_vault";

/// Programme pow-treasury ID (typed constant, no runtime string parsing)
pub const TREASURY_PROGRAM_ID: anchor_lang::prelude::Pubkey = anchor_lang::prelude::Pubkey::new_from_array([
    4, 247, 26, 137, 96, 251, 198, 158, 253, 26, 229, 138, 160, 93, 84, 8,
    185, 145, 112, 53, 116, 14, 130, 17, 2, 87, 220, 150, 193, 192, 166, 184,
]);

