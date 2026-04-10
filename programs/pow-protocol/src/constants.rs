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
// FEE PARAMETERS (Fee SOL progressive)
// =============================================================================

/// Fee initiale: 0.001 SOL (en lamports)
pub const FEE_INITIAL_SOL: u64 = 1_000_000; // 0.001 SOL = 1,000,000 lamports

/// Multiplicateur tous les 2 ans: 1.5x
pub const FEE_MULTIPLIER_NUMERATOR: u64 = 150;
pub const FEE_MULTIPLIER_DENOMINATOR: u64 = 100;

/// Fee maximum: 0.5 SOL (en lamports)
pub const FEE_SOL_CAP: u64 = 500_000_000; // 0.5 SOL = 500,000,000 lamports

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

