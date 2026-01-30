// =============================================================================
// ERREURS CUSTOM DU PROTOCOLE POW
// =============================================================================

use anchor_lang::prelude::*;

#[error_code]
pub enum PowError {
    // =============================================================================
    // ERREURS DE PREUVE (PoW)
    // =============================================================================
    
    #[msg("Invalid proof: hash does not meet difficulty target")]
    InvalidProof,

    #[msg("Invalid nonce provided")]
    InvalidNonce,

    #[msg("Challenge has expired, please get a new one")]
    ChallengeExpired,

    #[msg("Challenge not found or already used")]
    ChallengeNotFound,

    // =============================================================================
    // ERREURS D'ÉTAT
    // =============================================================================

    #[msg("Protocol is not yet initialized")]
    NotInitialized,

    #[msg("Protocol is already initialized")]
    AlreadyInitialized,

    #[msg("Protocol is paused")]
    ProtocolPaused,

    #[msg("Mining has not started yet")]
    MiningNotStarted,

    #[msg("Max supply reached, no more tokens can be mined")]
    MaxSupplyReached,

    // =============================================================================
    // ERREURS D'AUTORISATION
    // =============================================================================

    #[msg("Unauthorized: caller is not the authority")]
    Unauthorized,

    #[msg("Invalid authority provided")]
    InvalidAuthority,

    #[msg("Invalid mint address")]
    InvalidMint,

    // =============================================================================
    // ERREURS DE CALCUL
    // =============================================================================

    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Arithmetic underflow")]
    Underflow,

    #[msg("Division by zero")]
    DivisionByZero,

    #[msg("Invalid calculation result")]
    InvalidCalculation,

    // =============================================================================
    // ERREURS DE FEE
    // =============================================================================

    #[msg("Insufficient SOL for mining fee")]
    InsufficientFeePayment,

    #[msg("Fee calculation error")]
    FeeCalculationError,

    #[msg("Fee vault is empty")]
    EmptyFeeVault,

    // =============================================================================
    // ERREURS DE TIMING
    // =============================================================================

    #[msg("Block submitted too quickly, please wait")]
    BlockTooFast,

    #[msg("Invalid timestamp")]
    InvalidTimestamp,

    // =============================================================================
    // ERREURS DE CONFIGURATION
    // =============================================================================

    #[msg("Invalid difficulty value")]
    InvalidDifficulty,

    #[msg("Invalid reward value")]
    InvalidReward,

    #[msg("Invalid fee percentage")]
    InvalidFeePercentage,

    // =============================================================================
    // ERREURS AMM / LP
    // =============================================================================

    #[msg("AMM operation failed")]
    AmmOperationFailed,

    #[msg("Insufficient liquidity")]
    InsufficientLiquidity,

    #[msg("Slippage tolerance exceeded")]
    SlippageExceeded,

    #[msg("Invalid pool address")]
    InvalidPool,

    // =============================================================================
    // ERREURS DE COMPTE
    // =============================================================================

    #[msg("Invalid account data")]
    InvalidAccountData,

    #[msg("Account not writable")]
    AccountNotWritable,

    #[msg("Invalid PDA derivation")]
    InvalidPDA,

    #[msg("Account already exists")]
    AccountAlreadyExists,
}
