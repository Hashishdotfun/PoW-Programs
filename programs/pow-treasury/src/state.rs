// =============================================================================
// STATE DU PROGRAMME TREASURY
// =============================================================================

use anchor_lang::prelude::*;

/// CycleGate from pow-protocol (read-only mirror for deserialization)
/// Must match the layout in pow-protocol's state.rs
#[account]
pub struct CycleGate {
    pub cycle_number: u64,
    pub block_number: u64,
    pub timestamp: i64,
    pub is_consumed: bool,
    pub bump: u8,
}

/// Configuration et état du cycle treasury
///
/// Chaque mega/super-mega ouvre un cycle qui déclenche les DEUX phases en série:
/// - Phase A (Buyback) : Swap SOL→Token via Meteora DAMM v2, burn 50%, garder 50%
/// - Phase B (LP) : Add liquidity avec tokens du buyback + 66% du SOL résiduel
///
/// Les deux phases sont exécutées par le cranker en 2 tx séparées :
/// - Buyback toujours en premier (require: gate.cycle > last_consumed_buyback_cycle)
/// - LP ensuite (require: gate.cycle == last_consumed_buyback_cycle && gate.cycle > last_consumed_lp_cycle)
#[account]
pub struct TreasuryConfig {
    /// Authority admin (même que pow-protocol)
    pub authority: Pubkey,

    /// Programme pow-protocol ID (pour validation CPI)
    pub pow_protocol: Pubkey,

    /// HASHISH token mint
    pub mint: Pubkey,

    /// Meteora DAMM v2 pool address
    pub damm_pool: Pubkey,

    // =========================================================================
    // CYCLE STATE
    // =========================================================================

    /// DEPRECATED — kept for layout compatibility, no longer used.
    /// Phases sont maintenant indépendantes (buyback puis LP par cycle).
    pub current_phase: u8,

    /// Block count au début du cycle courant (lu depuis pow_config)
    pub cycle_start_block: u64,

    /// Tokens accumulés pour LP (carry over entre cycles)
    pub tokens_for_lp: u64,

    /// Timestamp du dernier cycle exécuté
    pub last_cycle_ts: i64,

    /// Nombre total de cycles complétés
    pub total_cycles: u64,

    /// Cycle actif ou non
    pub is_enabled: bool,

    // =========================================================================
    // LP TRACKING
    // =========================================================================

    /// Nombre de positions LP créées
    pub total_lp_positions: u64,

    /// Slippage maximum en basis points (ex: 100 = 1%)
    pub max_slippage_bps: u16,

    /// Compteur de tentatives échouées consécutives
    pub cycle_attempts: u8,

    // =========================================================================
    // STATS
    // =========================================================================

    /// Total SOL swappé via buyback
    pub total_sol_swapped: u64,

    /// Total tokens brûlés via buyback
    pub total_tokens_burned: u64,

    /// Total tokens envoyés en LP
    pub total_tokens_to_lp: u64,

    /// Total SOL envoyé en LP
    pub total_sol_to_lp: u64,

    /// Total rewards payées aux crankers
    pub total_cranker_rewards: u64,

    /// Dernier cycle_number consommé par execute_buyback (Phase A)
    pub last_consumed_buyback_cycle: u64,

    /// Dernier cycle_number consommé par execute_lp (Phase B).
    /// Doit toujours rester ≤ last_consumed_buyback_cycle (LP suit le buyback).
    pub last_consumed_lp_cycle: u64,

    /// Bump du PDA
    pub bump: u8,

    /// Position LP permanente — DAMM v2 position PDA (set une fois, réutilisée)
    pub lp_position: Pubkey,

    /// Position NFT mint (DAMM v2 uses NFT to represent positions)
    pub position_nft_mint: Pubkey,
}

impl TreasuryConfig {
    pub const LEN: usize = 8  // discriminator
        + 32  // authority
        + 32  // pow_protocol
        + 32  // mint
        + 32  // damm_pool
        + 1   // current_phase
        + 8   // cycle_start_block
        + 8   // tokens_for_lp
        + 8   // last_cycle_ts
        + 8   // total_cycles
        + 1   // is_enabled
        + 8   // total_lp_positions
        + 2   // max_slippage_bps
        + 1   // cycle_attempts
        + 8   // total_sol_swapped
        + 8   // total_tokens_burned
        + 8   // total_tokens_to_lp
        + 8   // total_sol_to_lp
        + 8   // total_cranker_rewards
        + 8   // last_consumed_buyback_cycle
        + 8   // last_consumed_lp_cycle
        + 1   // bump
        + 32  // lp_position
        + 32  // position_nft_mint
        + 16; // padding for future fields
}
