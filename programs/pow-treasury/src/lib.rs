// =============================================================================
// POW TREASURY - Programme de gestion de la trésorerie
// =============================================================================
// Programme séparé de pow-protocol pour la gestion automatisée:
// - Buyback & burn (swap SOL→Token via Meteora DAMM v2, burn 50%)
// - Add liquidity (ajout LP avec tokens + SOL)
// - Claim LP fees (récupérer les trading fees)
//
// Cycle alternant de 10 blocs:
// Phase A (Buyback): swap + burn 50% + garder 50%
// Phase B (LP): add liquidity avec tokens + SOL
//
// Cranker incentive: 0.1% du montant traité
// LP locked forever: pas de withdraw, seulement claim fees

use anchor_lang::prelude::*;

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;

#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "Hashish PoW Treasury",
    project_url: "https://hashish.fun",
    contacts: "email:admin@hashish.fun",
    policy: "https://github.com/Hashishdotfun/PoW-Programs/blob/main/SECURITY.md",
    preferred_languages: "en,fr",
    source_code: "https://github.com/Hashishdotfun/PoW-Programs",
    auditors: "N/A"
}

pub mod constants;
pub mod errors;
pub mod state;
pub mod instructions;
pub mod meteora_cpi;

use instructions::*;

declare_id!("LPAtdQ9sYQGXNs3RejVcWgi2u516nedpHABdwzmQish");

#[program]
pub mod pow_treasury {
    use super::*;

    // =========================================================================
    // INITIALISATION
    // =========================================================================

    /// Initialise le programme treasury
    ///
    /// Crée le TreasuryConfig PDA et les vaults.
    /// Doit être appelé une fois par l'authority du protocole.
    ///
    /// # Arguments
    /// - `damm_pool`: Adresse du pool Meteora DAMM v2 HASHISH/SOL
    /// - `max_slippage_bps`: Slippage maximum en basis points
    pub fn initialize(
        ctx: Context<InitializeTreasury>,
        damm_pool: Pubkey,
        max_slippage_bps: u16,
    ) -> Result<()> {
        instructions::initialize::handler(ctx, damm_pool, max_slippage_bps)
    }

    // =========================================================================
    // POOL CONFIGURATION
    // =========================================================================

    /// Configure le pool Meteora DAMM v2
    ///
    /// Crée le wSOL vault et enregistre l'adresse du pool.
    /// Peut être appelé après initialize() quand le pool est prêt.
    pub fn initialize_pool(
        ctx: Context<InitializePool>,
        damm_pool: Pubkey,
        max_slippage_bps: u16,
    ) -> Result<()> {
        instructions::initialize_pool::handler(ctx, damm_pool, max_slippage_bps)
    }

    // =========================================================================
    // LP POSITION
    // =========================================================================

    /// Initialise la position LP permanente dans le pool Meteora DAMM v2
    ///
    /// Authority only. Appelé une seule fois.
    /// Crée un NFT mint pour représenter la position.
    /// La position est réutilisée par execute_lp_cycle à chaque cycle.
    pub fn initialize_lp_position<'info>(
        ctx: Context<'_, '_, '_, 'info, InitializeLpPosition<'info>>,
    ) -> Result<()> {
        instructions::initialize_lp_position::handler(ctx)
    }

    // =========================================================================
    // FUND TREASURY
    // =========================================================================

    // =========================================================================
    // CYCLE BUYBACK (Phase A)
    // =========================================================================

    /// Exécute le cycle de buyback
    ///
    /// Permissionless avec incentive cranker (~0.1%).
    /// Swap SOL→HASHISH via Meteora DAMM v2, burn 50%, garder 50% pour LP.
    /// Slippage protection: min_amount_out calculé on-chain depuis les vault balances (x*y=k).
    pub fn execute_buyback_cycle<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecuteBuybackCycle<'info>>,
    ) -> Result<()> {
        instructions::execute_buyback::handler(ctx)
    }

    // =========================================================================
    // CYCLE LP (Phase B)
    // =========================================================================

    /// Exécute le cycle d'ajout de liquidité
    ///
    /// Permissionless avec incentive cranker (~0.1%).
    /// Ajoute liquidité avec tokens du buyback + SOL frais.
    /// Si pas assez de SOL, ajoute ce qu'on peut.
    pub fn execute_lp_cycle<'info>(
        ctx: Context<'_, '_, '_, 'info, ExecuteLpCycle<'info>>,
    ) -> Result<()> {
        instructions::execute_lp::handler(ctx)
    }

    // =========================================================================
    // CLAIM LP FEES
    // =========================================================================

    /// Claim les trading fees des positions LP
    ///
    /// Authority only (manuel).
    /// wSOL → wsol_vault (réutilisable)
    /// HASHISH → treasury_token_vault
    pub fn claim_lp_fees(ctx: Context<ClaimLpFees>) -> Result<()> {
        instructions::claim_lp_fees::handler(ctx)
    }

    // =========================================================================
    // LOCK LP POSITION (permanent)
    // =========================================================================

    /// Permanently lock all unlocked liquidity in the treasury LP position.
    ///
    /// Permissionless. Irreversible — locked liquidity can never be withdrawn.
    /// Fees can still be claimed on locked positions.
    /// Also called automatically at the end of each execute_lp_cycle.
    pub fn lock_lp_position<'info>(
        ctx: Context<'_, '_, '_, 'info, LockLpPosition<'info>>,
    ) -> Result<()> {
        instructions::lock_lp_position::handler(ctx)
    }

    /// One-shot migration: rewrites the on-chain TreasuryConfig from V1 to V2
    /// layout (shifting lp_position / position_nft_mint by 8 bytes after the
    /// inserted last_consumed_lp_cycle field, fixing the bump byte). Idempotent.
    /// Authority-only.
    pub fn migrate_treasury_v2(ctx: Context<MigrateTreasuryV2>) -> Result<()> {
        instructions::migrate_treasury_v2::handler(ctx)
    }
}
