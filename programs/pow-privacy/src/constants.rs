/// PDA Seeds
pub const PRIVACY_CONFIG_SEED: &[u8] = b"privacy_config";
pub const PRIVACY_AUTHORITY_SEED: &[u8] = b"privacy_authority";
pub const SHARED_TOKEN_VAULT_SEED: &[u8] = b"shared_token_vault";
pub const SHARED_FEE_VAULT_SEED: &[u8] = b"shared_fee_vault";
pub const CLAIM_SEED: &[u8] = b"claim";
pub const ENCRYPTED_STATE_SEED: &[u8] = b"encrypted_state";
pub const CLAIM_BUFFER_SEED: &[u8] = b"claim_buffer";
pub const CLAIM_REQUEST_BUFFER_SEED: &[u8] = b"claim_request_buffer";

/// Miner balance tracking seeds
pub const DEPOSIT_BUFFER_SEED: &[u8] = b"deposit_buffer";
pub const WITHDRAW_BUFFER_SEED: &[u8] = b"withdraw_buffer";
pub const MINE_BLOCK_BUFFER_SEED: &[u8] = b"mine_block_buffer";

/// Transfer Hook Seeds (from transfer_hook program)
pub const HOOK_EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";
pub const HOOK_FEE_VAULT_SEED: &[u8] = b"fee_vault";
pub const POW_CONFIG_SEED: &[u8] = b"pow_config";

/// Arcium MPC configuration
/// These will be updated when Arcium SDK is integrated
pub const ARCIUM_PROGRAM_ID: &str = "Arc1111111111111111111111111111111111111111";

/// Protocol limits
/// 4 ciphertext chunks × 32 bytes each = 128 bytes (circuit expects 4 ciphertexts for [u64; 4])
pub const MAX_ENCRYPTED_DESTINATION_LEN: usize = 4 * 32;
pub const MAX_PENDING_CLAIMS: u64 = 1_000_000;

/// Claim expiry (seconds) - claims can be made within 1 year
pub const CLAIM_EXPIRY_SECONDS: i64 = 365 * 24 * 60 * 60;

/// pow-protocol submit_proof discriminator
pub const SUBMIT_PROOF_DISCRIMINATOR: [u8; 8] = [54, 241, 46, 84, 4, 212, 46, 94];
