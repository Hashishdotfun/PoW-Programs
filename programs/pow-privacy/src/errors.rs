use anchor_lang::prelude::*;

// Note: Named ErrorCode (not ErrorCode) because Arcium macros
// expect ErrorCode::ClusterNotSet specifically
#[error_code]
pub enum ErrorCode {
    #[msg("Protocol is not active")]
    ProtocolInactive,

    #[msg("Unauthorized access")]
    Unauthorized,

    #[msg("Invalid proof of work")]
    InvalidProofOfWork,

    #[msg("Invalid claim secret")]
    InvalidClaimSecret,

    #[msg("Claim already processed")]
    ClaimAlreadyProcessed,

    #[msg("Claim not found")]
    ClaimNotFound,

    #[msg("Claim expired")]
    ClaimExpired,

    #[msg("Encrypted destination too long")]
    EncryptedDestinationTooLong,

    #[msg("Insufficient fee balance")]
    InsufficientFeeBalance,

    #[msg("Insufficient token balance")]
    InsufficientTokenBalance,

    #[msg("Arithmetic overflow")]
    Overflow,

    #[msg("Division by zero")]
    DivisionByZero,

    #[msg("Invalid program for CPI")]
    InvalidProgram,

    #[msg("Max pending claims reached")]
    MaxPendingClaimsReached,

    #[msg("Arcium verification failed")]
    ArciumVerificationFailed,

    #[msg("Invalid encrypted data")]
    InvalidEncryptedData,

    #[msg("Destination decryption failed")]
    DestinationDecryptionFailed,

    #[msg("Arcium cluster not set")]
    ClusterNotSet,

    #[msg("Claim buffer has already been used")]
    ClaimBufferAlreadyUsed,

    #[msg("Protocol is paused")]
    ProtocolPaused,

    #[msg("Buffer has already been used")]
    BufferAlreadyUsed,

    #[msg("Buffer is already complete")]
    BufferAlreadyComplete,

    #[msg("Buffer is not complete")]
    BufferIncomplete,

    #[msg("Buffer overflow - too much data")]
    BufferOverflow,

    #[msg("Unauthorized claimer")]
    UnauthorizedClaimer,

    #[msg("Invalid destination account")]
    InvalidDestination,

    #[msg("Invalid amount")]
    InvalidAmount,

    #[msg("Invalid owner")]
    InvalidOwner,

    #[msg("Insufficient balance in MPC state")]
    InsufficientBalance,
}
