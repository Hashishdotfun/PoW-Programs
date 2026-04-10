// =============================================================================
// ERREURS DU PROGRAMME TREASURY
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum TreasuryError {
    // =============================================================================
    // ERREURS D'AUTORISATION
    // =============================================================================

    #[msg("Unauthorized: caller is not the authority")]
    Unauthorized,

    #[msg("Invalid pow-protocol program ID")]
    InvalidPowProtocol,

    // =============================================================================
    // ERREURS DE CYCLE
    // =============================================================================

    #[msg("Cycle not ready: not enough blocks have passed")]
    CycleNotReady,

    #[msg("Wrong cycle phase for this operation")]
    WrongPhase,

    #[msg("Treasury cycle is disabled")]
    CycleDisabled,

    #[msg("No SOL available for this operation")]
    InsufficientSol,

    #[msg("No tokens available for this operation")]
    InsufficientTokens,

    // =============================================================================
    // ERREURS AMM / METEORA
    // =============================================================================

    #[msg("Meteora swap failed")]
    SwapFailed,

    #[msg("Meteora add liquidity failed")]
    AddLiquidityFailed,

    #[msg("Slippage tolerance exceeded")]
    SlippageExceeded,

    #[msg("Invalid pool address")]
    InvalidPool,

    #[msg("Meteora claim fees failed")]
    ClaimFeesFailed,

    // =============================================================================
    // ERREURS DE CALCUL
    // =============================================================================

    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Arithmetic underflow")]
    Underflow,

    #[msg("Division by zero")]
    DivisionByZero,

    // =============================================================================
    // ERREURS DE CONFIGURATION
    // =============================================================================

    #[msg("Invalid slippage value")]
    InvalidSlippage,

    #[msg("Treasury already initialized")]
    AlreadyInitialized,

    #[msg("Position does not match the stored LP position")]
    InvalidPosition,

    #[msg("LP position not initialized — call initialize_lp_position first")]
    PositionNotInitialized,
}
