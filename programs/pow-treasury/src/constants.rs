// =============================================================================
// CONSTANTES DU PROGRAMME TREASURY
// =============================================================================

// =============================================================================
// SEEDS FOR PDAs
// =============================================================================

pub const TREASURY_CONFIG_SEED: &[u8] = b"treasury_config";
pub const TREASURY_SOL_VAULT_SEED: &[u8] = b"treasury_sol_vault";
pub const TREASURY_TOKEN_VAULT_SEED: &[u8] = b"treasury_token_vault";
pub const TREASURY_WSOL_VAULT_SEED: &[u8] = b"treasury_wsol_vault";
pub const METEORA_EVENT_AUTH_SEED: &[u8] = b"__event_authority";

/// Seed du CycleGate PDA dans pow-protocol
pub const CYCLE_GATE_SEED: &[u8] = b"cycle_gate";

// =============================================================================
// CYCLE PARAMETERS
// =============================================================================

/// Nombre de blocs par cycle (hardcodé)
pub const BLOCKS_PER_CYCLE: u64 = 10;

/// Phase Buyback (A)
pub const PHASE_BUYBACK: u8 = 0;

/// Phase LP (B)
pub const PHASE_LP: u8 = 1;

/// Maximum de tentatives avant d'augmenter le slippage
pub const MAX_CYCLE_ATTEMPTS: u8 = 3;

/// Slippage par défaut en basis points (1% = 100 bps)
pub const DEFAULT_MAX_SLIPPAGE_BPS: u16 = 100;

/// Slippage maximum absolu (100% = 10000 bps, no limit)
pub const ABSOLUTE_MAX_SLIPPAGE_BPS: u16 = 10000;

/// Incrément de slippage après échec (0.5% = 50 bps)
pub const SLIPPAGE_INCREMENT_BPS: u16 = 50;

// =============================================================================
// BUYBACK PARAMETERS
// =============================================================================

/// Pourcentage des tokens achetés qui sont brûlés (50%)
pub const BURN_PCT: u64 = 50;

/// Pourcentage des tokens achetés gardés pour LP (50%)
pub const LP_TOKEN_PCT: u64 = 50;

/// Pourcentage du SOL alloué au buyback (Phase A) sur le total disponible.
/// Chaque mega/super-mega : 66% va en buyback, 34% reste pour le LP de ce même cycle.
pub const BUYBACK_SOL_PCT: u64 = 66;

/// Pourcentage du SOL résiduel utilisé pour le LP (Phase B).
/// 100% = consomme tout ce qu'il reste après le buyback (soit ~34% du SOL initial).
pub const LP_SOL_WRAP_PCT: u64 = 100;

// =============================================================================
// CRANKER INCENTIVE
// =============================================================================

/// Reward du cranker en basis points du montant SOL traité (0.1% = 10 bps)
pub const CRANKER_REWARD_BPS: u64 = 10;

/// Reward minimum du cranker (5000 lamports = 0.000005 SOL)
pub const CRANKER_MIN_REWARD: u64 = 5_000;

// =============================================================================
// METEORA DAMM v2
// =============================================================================

/// Meteora DAMM v2 (cp_amm) Program ID (mainnet)
pub const METEORA_DAMM_PROGRAM_ID: &str = "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG";

/// DAMM v2 pool authority (constant PDA)
pub const DAMM_POOL_AUTHORITY: &str = "HLnpSz9h2S4hiLQ43rnSD9XkcUThA7B8hQMKmDaiTLcC";

/// wSOL mint address
pub const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

// =============================================================================
// DAMM v2 POOL ACCOUNT OFFSETS
// =============================================================================
// Pool account layout offsets for reading sqrt_price, token amounts, etc.
// Based on Pool struct from DAMM v2 IDL.
// 8 byte discriminator + PoolFeesStruct (variable) + fields
// sqrt_price is at a known offset — we read it to compute slippage.

/// Offset of sqrt_price (u128) in the Pool account data
/// 8 (discriminator) + PoolFeesStruct size + pubkeys + padding + liquidity + padding
/// This offset needs to be verified against the actual deployed program.
/// For now we compute min_amount_out from token vault balances (x*y=k).
pub const POOL_SQRT_PRICE_OFFSET: usize = 0; // Placeholder — use vault ratio instead
