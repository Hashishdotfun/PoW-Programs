use anchor_lang::prelude::*;

// ============================================================================
// PRIVACY CONFIG
// ============================================================================

/// Global privacy protocol configuration
#[account]
pub struct PrivacyConfig {
    /// Admin authority
    pub authority: Pubkey,

    /// Token mint (HASHISH token)
    pub mint: Pubkey,

    /// Total tokens distributed via privacy layer
    pub total_tokens_distributed: u64,

    /// Total blocks submitted via privacy layer
    pub total_blocks: u64,

    /// Protocol active flag
    pub is_active: bool,

    /// Creation timestamp
    pub created_at: i64,

    /// Bump seeds
    pub bump: u8,
    pub authority_bump: u8,
    pub token_vault_bump: u8,
    pub fee_vault_bump: u8,

    /// Team/treasury wallet for receiving SOL withdrawal fees
    pub team_wallet: Pubkey,

    /// Team/treasury token account for receiving HASHISH withdrawal fees
    pub team_token_account: Pubkey,

    /// Withdrawal fee in basis points (50 = 0.5%)
    pub withdrawal_fee_bps: u16,
}

impl PrivacyConfig {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // authority
        32 +    // mint
        8 +     // total_tokens_distributed
        8 +     // total_blocks
        1 +     // is_active
        8 +     // created_at
        1 +     // bump
        1 +     // authority_bump
        1 +     // token_vault_bump
        1 +     // fee_vault_bump
        32 +    // team_wallet
        32 +    // team_token_account
        2;      // withdrawal_fee_bps
}

/// Update privacy config arguments
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct PrivacyConfigArgs {
    pub is_active: Option<bool>,
    pub team_wallet: Option<Pubkey>,
    pub team_token_account: Option<Pubkey>,
    pub withdrawal_fee_bps: Option<u16>,
}

// ============================================================================
// SOL BALANCE BUFFERS
// ============================================================================

/// Buffer for depositing SOL to miner's encrypted balance
#[account]
pub struct DepositBuffer {
    /// Owner who created this buffer
    pub owner: Pubkey,
    /// Amount of lamports being deposited (plaintext for SOL transfer)
    pub amount: u64,
    /// Encrypted amount for MPC (1 x 32 bytes)
    pub encrypted_amount: [u8; 32],
    /// Encrypted current state (3 x 32 bytes for MinerState)
    pub encrypted_current_state: [[u8; 32]; 3],
    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],
    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,
    /// Whether this buffer has been consumed
    pub is_used: bool,
    /// Creation timestamp
    pub created_at: i64,
    /// Bump seed
    pub bump: u8,
}

impl DepositBuffer {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // owner
        8 +     // amount
        32 +    // encrypted_amount
        (3 * 32) +  // encrypted_current_state
        32 +    // client_pubkey
        16 +    // encryption_nonce
        1 +     // is_used
        8 +     // created_at
        1;      // bump
}

/// Buffer for withdrawing SOL from miner's encrypted balance
#[account]
pub struct WithdrawBuffer {
    /// Owner who created this buffer
    pub owner: Pubkey,
    /// Requested withdrawal amount in lamports
    pub amount: u64,
    /// Encrypted amount for MPC (1 x 32 bytes)
    pub encrypted_amount: [u8; 32],
    /// Encrypted destination pubkey (4 x 32 = 128 bytes)
    pub encrypted_destination: [[u8; 32]; 4],
    /// Encrypted current state (3 x 32 bytes for MinerState)
    pub encrypted_current_state: [[u8; 32]; 3],
    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],
    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,
    /// Whether this buffer has been consumed
    pub is_used: bool,
    /// Whether withdrawal was approved by MPC
    pub is_approved: bool,
    /// Decrypted destination (set after MPC verification)
    pub verified_destination: Pubkey,
    /// Verified amount (set after MPC verification)
    pub verified_amount: u64,
    /// Creation timestamp
    pub created_at: i64,
    /// Bump seed
    pub bump: u8,
}

impl WithdrawBuffer {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // owner
        8 +     // amount
        32 +    // encrypted_amount
        (4 * 32) +  // encrypted_destination
        (3 * 32) +  // encrypted_current_state
        32 +    // client_pubkey
        16 +    // encryption_nonce
        1 +     // is_used
        1 +     // is_approved
        32 +    // verified_destination
        8 +     // verified_amount
        8 +     // created_at
        1;      // bump
}

// ============================================================================
// TOKEN BALANCE BUFFERS (HASHISH)
// ============================================================================

/// Buffer for depositing HASHISH tokens to miner's encrypted token balance
/// Used after mining (credit reward) or manual token deposits
#[account]
pub struct DepositTokenBuffer {
    /// Owner who created this buffer
    pub owner: Pubkey,
    /// Amount of tokens being deposited (plaintext)
    pub amount: u64,
    /// Encrypted amount for MPC (1 x 32 bytes)
    pub encrypted_amount: [u8; 32],
    /// Encrypted current token state (3 x 32 bytes for MinerStateToken)
    pub encrypted_current_token_state: [[u8; 32]; 3],
    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],
    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,
    /// Whether this buffer has been consumed
    pub is_used: bool,
    /// Creation timestamp
    pub created_at: i64,
    /// Bump seed
    pub bump: u8,
}

impl DepositTokenBuffer {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // owner
        8 +     // amount
        32 +    // encrypted_amount
        (3 * 32) +  // encrypted_current_token_state
        32 +    // client_pubkey
        16 +    // encryption_nonce
        1 +     // is_used
        8 +     // created_at
        1;      // bump
}

/// Buffer for withdrawing HASHISH tokens from miner's encrypted token balance
#[account]
pub struct WithdrawTokenBuffer {
    /// Owner who created this buffer
    pub owner: Pubkey,
    /// Requested withdrawal amount (gross, before fee)
    pub amount: u64,
    /// Encrypted amount for MPC (1 x 32 bytes)
    pub encrypted_amount: [u8; 32],
    /// Encrypted destination pubkey (4 x 32 = 128 bytes)
    pub encrypted_destination: [[u8; 32]; 4],
    /// Encrypted current token state (3 x 32 bytes for MinerStateToken)
    pub encrypted_current_token_state: [[u8; 32]; 3],
    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],
    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,
    /// Whether this buffer has been consumed
    pub is_used: bool,
    /// Whether withdrawal was approved by MPC
    pub is_approved: bool,
    /// Whether the token transfer has been executed
    pub is_executed: bool,
    /// Decrypted destination (set after MPC verification)
    pub verified_destination: Pubkey,
    /// Verified amount (set after MPC verification)
    pub verified_amount: u64,
    /// Creation timestamp
    pub created_at: i64,
    /// Bump seed
    pub bump: u8,
}

impl WithdrawTokenBuffer {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // owner
        8 +     // amount
        32 +    // encrypted_amount
        (4 * 32) +  // encrypted_destination
        (3 * 32) +  // encrypted_current_token_state
        32 +    // client_pubkey
        16 +    // encryption_nonce
        1 +     // is_used
        1 +     // is_approved
        1 +     // is_executed
        32 +    // verified_destination
        8 +     // verified_amount
        8 +     // created_at
        1;      // bump
}

// ============================================================================
// EVENTS
// ============================================================================

#[event]
pub struct PrivacyProtocolInitialized {
    pub config: Pubkey,
    pub authority: Pubkey,
    pub mint: Pubkey,
}

#[event]
pub struct BlockMinedPrivate {
    /// Reward amount (tokens)
    pub reward_amount: u64,
    /// Block number in pow-protocol
    pub block_number: u64,
    /// Timestamp
    pub timestamp: i64,
}

#[event]
pub struct FeeDeposited {
    pub amount: u64,
    pub new_balance: u64,
}

#[event]
pub struct ConfigUpdated {
    pub is_active: Option<bool>,
    pub team_wallet: Option<Pubkey>,
    pub team_token_account: Option<Pubkey>,
    pub withdrawal_fee_bps: Option<u16>,
}

#[event]
pub struct MpcComputationQueued {
    pub computation_type: String,
    pub timestamp: i64,
}

// SOL balance events

#[event]
pub struct DepositBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct DepositProcessed {
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct WithdrawBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct SolWithdrawProcessed {
    pub gross_amount: u64,
    pub fee_amount: u64,
    pub net_amount: u64,
    pub destination: Pubkey,
    pub timestamp: i64,
}

// Token balance events

#[event]
pub struct DepositTokenBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct DepositTokenProcessed {
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct WithdrawTokenBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct TokenWithdrawProcessed {
    pub gross_amount: u64,
    pub fee_amount: u64,
    pub net_amount: u64,
    pub destination: Pubkey,
    pub timestamp: i64,
}

// ============================================================================
// MPC CIRCUIT OUTPUT TYPES (Arcium encrypted-ixs)
// ============================================================================

/// Miner SOL state (from Arcium MPC)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct MinerState {
    pub balance: u64,
    pub nonce: u64,
    pub reserved: u64,
}

/// Result of mining a block (deducting protocol fee)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct MineBlockResult {
    pub new_balance: u64,
    pub fee_deducted: u64,
    pub success: bool,
}

/// Result of depositing SOL
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct DepositFeeResult {
    pub new_balance: u64,
    pub success: bool,
}

/// Result of withdrawing SOL
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct WithdrawFeeResult {
    pub destination: [u64; 4],
    pub amount: u64,
    pub new_balance: u64,
    pub success: bool,
}

/// Result of depositing HASHISH tokens
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct DepositTokenResult {
    pub new_token_balance: u64,
    pub success: bool,
}

/// Result of withdrawing HASHISH tokens
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct WithdrawTokenResult {
    pub destination: [u64; 4],
    pub amount: u64,
    pub new_token_balance: u64,
    pub success: bool,
}
