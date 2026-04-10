/// PDA Seeds
pub const PRIVACY_CONFIG_SEED: &[u8] = b"privacy_config";
pub const PRIVACY_AUTHORITY_SEED: &[u8] = b"privacy_authority";
pub const SHARED_TOKEN_VAULT_SEED: &[u8] = b"shared_token_vault";
pub const SHARED_FEE_VAULT_SEED: &[u8] = b"shared_fee_vault";

/// Miner SOL balance tracking seeds
pub const DEPOSIT_BUFFER_SEED: &[u8] = b"deposit_buffer";
pub const WITHDRAW_BUFFER_SEED: &[u8] = b"withdraw_buffer";
pub const MINE_BLOCK_BUFFER_SEED: &[u8] = b"mine_block_buffer";

/// Miner HASHISH token balance tracking seeds
pub const DEPOSIT_TOKEN_BUFFER_SEED: &[u8] = b"deposit_token_buffer";
pub const WITHDRAW_TOKEN_BUFFER_SEED: &[u8] = b"withdraw_token_buffer";

/// Transfer Hook Seeds (from transfer_hook program)
pub const HOOK_EXTRA_ACCOUNT_METAS_SEED: &[u8] = b"extra-account-metas";
pub const HOOK_FEE_VAULT_SEED: &[u8] = b"fee_vault";
pub const POW_CONFIG_SEED: &[u8] = b"pow_config";
pub const MINT_AUTHORITY_SEED: &[u8] = b"pow_mint_auth";
pub const DEVICE_ATTEST_SEED: &[u8] = b"device_attest";

/// Pool IDs (privacy uses normal pool only)
pub const POOL_NORMAL: u8 = 0;
pub const POOL_SEEKER: u8 = 1;

/// Arcium MPC configuration
pub const ARCIUM_PROGRAM_ID: &str = "Arc1111111111111111111111111111111111111111";

/// Protocol limits
/// 4 ciphertext chunks × 32 bytes each = 128 bytes (circuit expects 4 ciphertexts for [u64; 4])
pub const MAX_ENCRYPTED_DESTINATION_LEN: usize = 4 * 32;

/// Withdrawal fee configuration
pub const DEFAULT_WITHDRAWAL_FEE_BPS: u16 = 50; // 0.5%
pub const BPS_DENOMINATOR: u64 = 10_000;

/// pow-protocol submit_proof discriminator
pub const SUBMIT_PROOF_DISCRIMINATOR: [u8; 8] = [54, 241, 46, 84, 4, 212, 46, 94];
