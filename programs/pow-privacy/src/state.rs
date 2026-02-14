use anchor_lang::prelude::*;

use crate::constants::MAX_ENCRYPTED_DESTINATION_LEN;

/// Global privacy protocol configuration
#[account]
pub struct PrivacyConfig {
    /// Admin authority
    pub authority: Pubkey,

    /// Token mint (HASH token)
    pub mint: Pubkey,

    /// Next claim ID (auto-increment)
    pub next_claim_id: u64,

    /// Total claims created
    pub total_claims: u64,

    /// Total claims processed
    pub total_claims_processed: u64,

    /// Total tokens distributed via claims
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
}

impl PrivacyConfig {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // authority
        32 +    // mint
        8 +     // next_claim_id
        8 +     // total_claims
        8 +     // total_claims_processed
        8 +     // total_tokens_distributed
        8 +     // total_blocks
        1 +     // is_active
        8 +     // created_at
        1 +     // bump
        1 +     // authority_bump
        1 +     // token_vault_bump
        1;      // fee_vault_bump
}

/// Individual claim record
/// Each block mined creates one claim with encrypted destination
#[account]
pub struct Claim {
    /// Claim ID (unique, sequential)
    pub id: u64,

    /// Token amount to claim
    pub amount: u64,

    /// Encrypted destination wallet (Arcium encrypted)
    /// 4 x 32-byte ciphertexts flattened = 128 bytes
    /// Only Arcium MPC can decrypt this
    pub encrypted_destination: Vec<u8>,

    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],

    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,

    /// Hash of the claim secret (SHA256)
    /// Miner must provide preimage to claim
    pub secret_hash: [u8; 32],

    /// Whether this claim has been processed
    pub is_claimed: bool,

    /// Whether MPC verification is pending
    pub verification_pending: bool,

    /// Block number when this claim was created
    pub block_number: u64,

    /// Timestamp when claim was created
    pub created_at: i64,

    /// Timestamp when claim was processed (0 if not claimed)
    pub claimed_at: i64,

    /// Bump seed
    pub bump: u8,
}

impl Claim {
    pub const LEN: usize = 8 +  // discriminator
        8 +     // id
        8 +     // amount
        4 + MAX_ENCRYPTED_DESTINATION_LEN +  // encrypted_destination (vec)
        32 +    // client_pubkey
        16 +    // encryption_nonce
        32 +    // secret_hash
        1 +     // is_claimed
        1 +     // verification_pending
        8 +     // block_number
        8 +     // created_at
        8 +     // claimed_at
        1;      // bump
}

/// Encrypted state managed by Arcium
/// This is a placeholder - actual implementation will use Arcium SDK
#[account]
pub struct EncryptedState {
    /// Reference to privacy config
    pub config: Pubkey,

    /// Arcium MXE (Multi-party eXecution Environment) ID
    pub mxe_id: [u8; 32],

    /// Encrypted balance mapping root (Merkle root or similar)
    /// This allows verification without revealing individual balances
    pub balance_root: [u8; 32],

    /// Number of entries in encrypted state
    pub entry_count: u64,

    /// Last update timestamp
    pub last_update: i64,

    /// Bump seed
    pub bump: u8,
}

impl EncryptedState {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // config
        32 +    // mxe_id
        32 +    // balance_root
        8 +     // entry_count
        8 +     // last_update
        1;      // bump
}

/// Temporary buffer for storing encrypted claim data
/// Used to split large encrypted payloads across multiple transactions
#[account]
pub struct ClaimBuffer {
    /// Owner who created this buffer (can close it)
    pub owner: Pubkey,

    /// Encrypted claim ciphertexts (34 x 32 bytes = 1088 bytes)
    pub encrypted_claim_bytes: Vec<u8>,

    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],

    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,

    /// Hash of the claim secret (SHA256)
    pub secret_hash: [u8; 32],

    /// Whether this buffer has been consumed
    pub is_used: bool,

    /// Creation timestamp
    pub created_at: i64,

    /// Bump seed
    pub bump: u8,
}

impl ClaimBuffer {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // owner
        4 + MAX_ENCRYPTED_DESTINATION_LEN +  // encrypted_claim_bytes (vec: 4 + 1088)
        32 +    // client_pubkey
        16 +    // encryption_nonce
        32 +    // secret_hash
        1 +     // is_used
        8 +     // created_at
        1;      // bump
}

/// Temporary buffer for storing encrypted claim request data
/// Used for claim_reward instruction
/// Stores: encrypted_claim_id (1 × 32 bytes for Enc<Shared, u64>) + encrypted_secret (4 × 32 = 128 bytes for [u64; 4])
#[account]
pub struct ClaimRequestBuffer {
    /// Owner who created this buffer (claimer)
    pub owner: Pubkey,

    /// Claim ID being requested (plaintext for verification)
    pub claim_id: u64,

    /// Encrypted claim ID ciphertext (1 × 32 bytes for Enc<Shared, u64>)
    pub encrypted_claim_id: [u8; 32],

    /// Encrypted secret ciphertexts (4 × 32 bytes = 128 bytes for [u64; 4])
    pub encrypted_secret: [[u8; 32]; 4],

    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],

    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,

    /// Plain secret (for local hash verification)
    pub secret: [u8; 32],

    /// Whether this buffer has been consumed
    pub is_used: bool,

    /// Creation timestamp
    pub created_at: i64,

    /// Bump seed
    pub bump: u8,
}

impl ClaimRequestBuffer {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // owner
        8 +     // claim_id
        32 +    // encrypted_claim_id (1 ciphertext)
        (4 * 32) +  // encrypted_secret (4 ciphertexts × 32 bytes = 128 bytes)
        32 +    // client_pubkey
        16 +    // encryption_nonce
        32 +    // secret
        1 +     // is_used
        8 +     // created_at
        1;      // bump
}

/// Update privacy config arguments
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct PrivacyConfigArgs {
    pub is_active: Option<bool>,
}

// ============================================================================
// MINER BALANCE TRACKING (Arcium MPC integration)
// ============================================================================

/// Buffer for depositing SOL to miner's encrypted balance
/// Used to store encrypted amount and current state for Arcium MPC
#[account]
pub struct DepositBuffer {
    /// Owner who created this buffer (depositor's public wallet)
    pub owner: Pubkey,

    /// Amount of lamports being deposited (plaintext for SOL transfer)
    pub amount: u64,

    /// Encrypted amount for MPC (1 x 32 bytes for Enc<Shared, u64>)
    pub encrypted_amount: [u8; 32],

    /// Encrypted current state (3 x 32 bytes for MinerState: balance, nonce, reserved)
    /// For new miners, this should be encrypted zeros
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
        32 +    // encrypted_amount (1 ciphertext)
        (3 * 32) +  // encrypted_current_state (3 ciphertexts)
        32 +    // client_pubkey
        16 +    // encryption_nonce
        1 +     // is_used
        8 +     // created_at
        1;      // bump
}

/// Buffer for withdrawing SOL from miner's encrypted balance
/// Stores encrypted data for Arcium MPC withdrawal verification
#[account]
pub struct WithdrawBuffer {
    /// Owner who created this buffer (can be throwaway or any wallet)
    pub owner: Pubkey,

    /// Requested withdrawal amount in lamports (plaintext for verification)
    pub amount: u64,

    /// Encrypted amount for MPC (1 x 32 bytes for Enc<Shared, u64>)
    pub encrypted_amount: [u8; 32],

    /// Encrypted destination pubkey (4 x 32 = 128 bytes for [u64; 4])
    /// This is where the SOL will be sent
    pub encrypted_destination: [[u8; 32]; 4],

    /// Encrypted current state (3 x 32 bytes for MinerState: balance, nonce, reserved)
    pub encrypted_current_state: [[u8; 32]; 3],

    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],

    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,

    /// Whether this buffer has been consumed
    pub is_used: bool,

    /// Whether withdrawal was approved by MPC
    pub is_approved: bool,

    /// Decrypted destination (set after MPC verification, 0s if pending)
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
        32 +    // encrypted_amount (1 ciphertext)
        (4 * 32) +  // encrypted_destination
        (3 * 32) +  // encrypted_current_state (3 ciphertexts)
        32 +    // client_pubkey
        16 +    // encryption_nonce
        1 +     // is_used
        1 +     // is_approved
        32 +    // verified_destination
        8 +     // verified_amount
        8 +     // created_at
        1;      // bump
}

/// Buffer for mining block with balance verification
/// Stores encrypted protocol fee and current state for Arcium MPC
#[account]
pub struct MineBlockBuffer {
    /// Owner who created this buffer (submitter)
    pub owner: Pubkey,

    /// Encrypted protocol fee amount (1 x 32 bytes)
    pub encrypted_protocol_fee: [u8; 32],

    /// Encrypted current state (3 x 32 bytes for MinerState: balance, nonce, reserved)
    pub encrypted_current_state: [[u8; 32]; 3],

    /// Client's x25519 public key for Arcium decryption
    pub client_pubkey: [u8; 32],

    /// Encryption nonce used with RescueCipher
    pub encryption_nonce: u128,

    /// Hash of the claim secret (SHA256) for claiming rewards
    pub secret_hash: [u8; 32],

    /// Whether this buffer has been consumed
    pub is_used: bool,

    /// Whether balance verification passed
    pub balance_verified: bool,

    /// Protocol fee amount (plaintext, for verification)
    pub protocol_fee: u64,

    /// Expected balance after deduction (0 = not computed yet)
    pub expected_balance_after: u64,

    /// Creation timestamp
    pub created_at: i64,

    /// Bump seed
    pub bump: u8,
}

impl MineBlockBuffer {
    pub const LEN: usize = 8 +  // discriminator
        32 +    // owner
        32 +    // encrypted_protocol_fee
        (3 * 32) +  // encrypted_current_state (3 ciphertexts)
        32 +    // client_pubkey
        16 +    // encryption_nonce
        32 +    // secret_hash
        1 +     // is_used
        1 +     // balance_verified
        8 +     // protocol_fee
        8 +     // expected_balance_after
        8 +     // created_at
        1;      // bump
}

// === EVENTS ===

#[event]
pub struct PrivacyProtocolInitialized {
    pub config: Pubkey,
    pub authority: Pubkey,
    pub mint: Pubkey,
}

#[event]
pub struct BlockSubmittedPrivate {
    /// Claim ID (public, but unlinkable to miner)
    pub claim_id: u64,
    /// Reward amount
    pub amount: u64,
    /// Block number in pow-protocol
    pub block_number: u64,
    /// Timestamp
    pub timestamp: i64,
    // NOTE: destination is NOT emitted - it's encrypted
}

#[event]
pub struct RewardClaimed {
    /// Claim ID
    pub claim_id: u64,
    /// Amount claimed
    pub amount: u64,
    /// Timestamp
    pub timestamp: i64,
    // NOTE: destination is NOT emitted - privacy preserved
}

#[event]
pub struct FeeDeposited {
    /// Amount deposited
    pub amount: u64,
    /// New vault balance
    pub new_balance: u64,
}

#[event]
pub struct ConfigUpdated {
    pub is_active: Option<bool>,
}

#[event]
pub struct ClaimVerificationQueued {
    pub claim_id: u64,
    pub timestamp: i64,
}

#[event]
pub struct MpcComputationQueued {
    pub computation_type: String,
    pub timestamp: i64,
}

#[event]
pub struct ClaimBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct ClaimBufferConsumed {
    pub buffer: Pubkey,
    pub claim_id: u64,
    pub timestamp: i64,
}

#[event]
pub struct ClaimRequestBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub claim_id: u64,
    pub timestamp: i64,
}

#[event]
pub struct ClaimRequestBufferConsumed {
    pub buffer: Pubkey,
    pub claim_id: u64,
    pub timestamp: i64,
}

// ============================================================================
// MINER BALANCE EVENTS
// ============================================================================

#[event]
pub struct DepositBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct DepositProcessed {
    /// Amount deposited in lamports
    pub amount: u64,
    /// Timestamp of processing
    pub timestamp: i64,
    // NOTE: miner_id_hash is NOT emitted - privacy preserved
}

#[event]
pub struct WithdrawBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct WithdrawProcessed {
    /// Amount withdrawn in lamports
    pub amount: u64,
    /// Destination pubkey (revealed after MPC verification)
    pub destination: Pubkey,
    /// Timestamp
    pub timestamp: i64,
}

#[event]
pub struct MineBlockBufferCreated {
    pub buffer: Pubkey,
    pub owner: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct BalanceVerified {
    /// Whether the miner has sufficient balance
    pub has_sufficient_balance: bool,
    /// The protocol fee that was verified
    pub protocol_fee: u64,
    /// Timestamp
    pub timestamp: i64,
}

// ============================================================================
// MPC CIRCUIT OUTPUT TYPES (Arcium encrypted-ixs)
// ============================================================================

/// Persistent state for a miner's encrypted balance (from Arcium MPC)
/// Corresponds to encrypted-ixs MinerState
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct MinerState {
    /// Current balance in lamports
    pub balance: u64,
    /// Transaction nonce (anti-replay)
    pub nonce: u64,
    /// Reserved for future use
    pub reserved: u64,
}

/// Result of mining a block (deducting protocol fee)
/// success: false triggers revert on-chain
/// Corresponds to encrypted-ixs MineBlockResult
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct MineBlockResult {
    /// New balance after fee deduction
    pub new_balance: u64,
    /// The protocol fee that was deducted
    pub fee_deducted: u64,
    /// Whether mining succeeded (enough balance)
    pub success: bool,
}

/// Result of depositing fee to miner's balance
/// Corresponds to encrypted-ixs DepositFeeResult
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct DepositFeeResult {
    /// New balance after deposit
    pub new_balance: u64,
    /// Whether deposit succeeded
    pub success: bool,
}

/// Result of withdrawing fees to a destination
/// Corresponds to encrypted-ixs WithdrawFeeResult
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy)]
pub struct WithdrawFeeResult {
    /// The destination pubkey to send SOL to (4 x u64 = 32 bytes)
    pub destination: [u64; 4],
    /// Amount to withdraw
    pub amount: u64,
    /// New balance after withdrawal
    pub new_balance: u64,
    /// Whether withdrawal succeeded
    pub success: bool,
}
