// =============================================================================
// CONSTANTES DU PROTOCOLE POW
// =============================================================================
// Basé sur les paramètres du document 2


// =============================================================================
// TOKEN PARAMETERS
// =============================================================================

/// Max supply: 1,000,000 tokens (avec 9 décimales)
pub const MAX_SUPPLY: u64 = 1_000_000 * DECIMALS_MULTIPLIER;

/// Decimales du token
pub const DECIMALS: u8 = 9;

/// Multiplicateur pour les décimales (10^9)
pub const DECIMALS_MULTIPLIER: u64 = 1_000_000_000;

/// Premint tokens pour LP initiale (1000 tokens)
pub const PREMINT_TOKENS: u64 = 1_000 * DECIMALS_MULTIPLIER;

// =============================================================================
// TIMING PARAMETERS
// =============================================================================

/// Target block time: 60 secondes
pub const TARGET_BLOCK_TIME: i64 = 60;

/// Secondes par an (approximatif)
pub const SECONDS_PER_YEAR: i64 = 365 * 24 * 60 * 60; // 31,536,000

/// Blocs par an (avec block time de 60s)
pub const BLOCKS_PER_YEAR: u64 = 525_600;

/// Blocs pour 2 ans
pub const BLOCKS_PER_2_YEARS: u64 = 1_051_200;

// =============================================================================
// REWARD PARAMETERS (Émission exponentielle décroissante)
// =============================================================================

/// Reward initial normal (après 1ère année) - ~0.0574 tokens par bloc
/// En base 10^9: 57_400_000
pub const R0_NORMAL: u64 = 57_400_000;

/// Reward initial boosté (1ère année, x1.5) - ~0.0887 tokens par bloc
/// En base 10^9: 88_700_000
pub const R0_BOOST: u64 = 88_700_000;

/// Facteur de décroissance k (en millionièmes pour précision)
/// k ≈ 0.999999943 → stocké comme 999_999_943 / 1_000_000_000
pub const DECAY_FACTOR_NUMERATOR: u128 = 999_999_943;
pub const DECAY_FACTOR_DENOMINATOR: u128 = 1_000_000_000;

/// Durée du boost en secondes (1 an)
pub const BOOST_DURATION: i64 = SECONDS_PER_YEAR;

// =============================================================================
// FEE PARAMETERS (Fee SOL progressive)
// =============================================================================

/// Fee initiale: 0.005 SOL (en lamports)
pub const FEE_INITIAL_SOL: u64 = 5_000_000; // 0.005 SOL = 5,000,000 lamports

/// Multiplicateur tous les 2 ans: 1.5x
/// Stocké comme 150 / 100 pour éviter les floats
pub const FEE_MULTIPLIER_NUMERATOR: u64 = 150;
pub const FEE_MULTIPLIER_DENOMINATOR: u64 = 100;

/// Fee maximum: 0.5 SOL (en lamports)
pub const FEE_SOL_CAP: u64 = 500_000_000; // 0.5 SOL = 500,000,000 lamports

// =============================================================================
// FEE DISTRIBUTION (Split des fees SOL)
// =============================================================================

/// Team fee: 5%
pub const TEAM_FEE_PCT: u64 = 5;

/// Protocol fee: 95% (LP + buyback)
pub const PROTO_FEE_PCT: u64 = 95;

/// Buyback: 60% du protocol fee
pub const BUYBACK_SOL_PCT: u64 = 60;

/// LP: 40% du protocol fee
pub const LP_SOL_PCT: u64 = 40;

/// Burn from buyback: 50%
pub const BURN_FROM_BUYBACK_PCT: u64 = 50;

/// LP from buyback: 50%
pub const LP_FROM_BUYBACK_PCT: u64 = 50;

// =============================================================================
// TRANSFER TAX (SPL2022)
// =============================================================================

/// Taxe de transfert: 0.01% = 1 basis point
pub const TRANSFER_TAX_BASIS_POINTS: u16 = 1;

/// % de la taxe qui est burn: 50%
pub const TRANSFER_BURN_PCT: u64 = 50;

/// % de la taxe pour les mineurs: 50%
pub const TRANSFER_MINER_PCT: u64 = 50;

// =============================================================================
// DIFFICULTY PARAMETERS
// =============================================================================

/// Difficulté initiale (ajuster selon le hashrate attendu)
/// Plus c'est grand, plus c'est difficile
/// Temporairement facile pour les tests locaux
pub const INITIAL_DIFFICULTY: u128 = 10_000;

/// Difficulté minimum (empêche de tomber à 0)
pub const MIN_DIFFICULTY: u128 = 1_000;

/// Difficulté maximum (empêche overflow)
pub const MAX_DIFFICULTY: u128 = u128::MAX / 1000;

// =============================================================================
// AJUSTEMENT PROPORTIONNEL DE DIFFICULTÉ
// =============================================================================
// L'ajustement est maintenant proportionnel au ratio temps_réel/temps_cible:
//
// ratio < 0.5   → Bloc très rapide (< 30s)  → ×2.0 (doubler)
// ratio < 0.75  → Bloc rapide (30-45s)      → ×1.5 (+50%)
// ratio < 0.9   → Bloc légèrement rapide    → ×1.1 (+10%)
// 0.9 ≤ ratio ≤ 1.1 → Dans la cible (54-66s) → ×1.0 (aucun changement)
// ratio ≤ 1.5   → Bloc légèrement lent      → ×0.9 (-10%)
// ratio ≤ 2.0   → Bloc lent (90-120s)       → ×0.7 (-30%)
// ratio > 2.0   → Bloc très lent (> 120s)   → ×0.5 (diviser par 2)
//
// Avantages:
// - Convergence 81% plus rapide (38 blocs vs 580 blocs pour 10k GPUs)
// - Réaction adaptative aux changements de hashrate
// - Zone de stabilité (±10% = pas de changement)
// =============================================================================

// Les anciennes constantes sont conservées pour compatibilité avec les tests
#[allow(dead_code)]
pub const DIFF_UP_FACTOR_NUMERATOR: u128 = 102;
#[allow(dead_code)]
pub const DIFF_UP_FACTOR_DENOMINATOR: u128 = 100;
#[allow(dead_code)]
pub const DIFF_DOWN_FACTOR_NUMERATOR: u128 = 98;
#[allow(dead_code)]
pub const DIFF_DOWN_FACTOR_DENOMINATOR: u128 = 100;
#[allow(dead_code)]
pub const SLOW_BLOCK_THRESHOLD_MULTIPLIER: i64 = 3;
#[allow(dead_code)]
pub const SLOW_BLOCK_THRESHOLD_DIVISOR: i64 = 2;

// =============================================================================
// LP PARAMETERS
// =============================================================================

/// LP initiale SOL: 0.1 SOL
pub const LP_INITIAL_SOL: u64 = 100_000_000; // 0.1 SOL = 100,000,000 lamports

/// LP initiale tokens: 1000 tokens (= tout le premint)
pub const LP_INITIAL_TOKENS: u64 = PREMINT_TOKENS;

// =============================================================================
// SEEDS FOR PDAs
// =============================================================================

pub const POW_CONFIG_SEED: &[u8] = b"pow_config";
pub const POW_VAULT_SEED: &[u8] = b"pow_vault";
pub const FEE_VAULT_SEED: &[u8] = b"fee_vault";
pub const TEAM_VAULT_SEED: &[u8] = b"team_vault";
pub const LP_VAULT_SEED: &[u8] = b"lp_vault";
pub const MINER_STATS_SEED: &[u8] = b"miner_stats";
