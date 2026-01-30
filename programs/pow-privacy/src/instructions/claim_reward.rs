use anchor_lang::prelude::*;
use solana_program::hash::hash;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;
// Import ID, ID_CONST, and ArciumSignerAccount for Arcium macros
use crate::{ID, ID_CONST, ArciumSignerAccount};

// Computation definition offset for verify_and_claim
const COMP_DEF_OFFSET_VERIFY_AND_CLAIM: u32 = comp_def_offset("verify_and_claim");

/// Build the ArgBuilder for verify_and_claim MPC computation
/// Input 1: Encrypted claim_id (1 ciphertext)
/// Input 2: Encrypted secret (4 ciphertexts for [u64; 4])
#[inline(never)]
fn build_verify_and_claim_args(
    // Input 1: claim_id (encrypted)
    claim_client_pubkey: [u8; 32],
    claim_encryption_nonce: u128,
    encrypted_claim_id: [u8; 32],       // 1 ciphertext for u64
    // Input 2: secret (encrypted)
    secret_client_pubkey: [u8; 32],
    secret_encryption_nonce: u128,
    encrypted_secret: [[u8; 32]; 4],    // 4 ciphertexts for [u64; 4]
) -> ArgumentList {
    ArgBuilder::new()
        // Input 1: encrypted claim_id
        .x25519_pubkey(claim_client_pubkey)
        .plaintext_u128(claim_encryption_nonce)
        .encrypted_u64(encrypted_claim_id)
        // Input 2: encrypted secret
        .x25519_pubkey(secret_client_pubkey)
        .plaintext_u128(secret_encryption_nonce)
        .encrypted_u64(encrypted_secret[0])
        .encrypted_u64(encrypted_secret[1])
        .encrypted_u64(encrypted_secret[2])
        .encrypted_u64(encrypted_secret[3])
        .build()
}

/// Claim rewards via Arcium MPC verification
///
/// Flow:
/// 1. Miner creates claim request buffer with encrypted claim_id and secret
/// 2. Miner calls this instruction
/// 3. Program queues Arcium MPC computation (verify_and_claim)
/// 4. MPC verifies hash(secret) == claim.secret_hash
/// 5. Callback transfers tokens to destination
///
/// Privacy properties:
/// - The claim_id and secret are encrypted with Arcium x25519
/// - MPC decrypts and verifies without revealing the secret
/// - The destination was encrypted when the block was submitted
pub fn handler(
    ctx: Context<ClaimReward>,
    computation_offset: u64,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let config = &ctx.accounts.privacy_config;
    let claim_request = &ctx.accounts.claim_request_buffer;
    let claim = &ctx.accounts.claim;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Verify claim not already processed
    require!(!claim.is_claimed, ErrorCode::ClaimAlreadyProcessed);

    // Verify claim not expired
    require!(
        now - claim.created_at < CLAIM_EXPIRY_SECONDS,
        ErrorCode::ClaimExpired
    );

    // Verify claim_id matches the buffer
    require!(
        claim_request.claim_id == claim.id,
        ErrorCode::ClaimNotFound
    );

    // Verify secret hash matches (using the plaintext secret from the buffer)
    let computed_hash = hash(&claim_request.secret);
    require!(
        computed_hash.to_bytes() == claim.secret_hash,
        ErrorCode::InvalidClaimSecret
    );

    // Build MPC arguments from the claim request buffer
    let args = build_verify_and_claim_args(
        claim_request.client_pubkey,
        claim_request.encryption_nonce,
        claim_request.encrypted_claim_id,
        claim_request.client_pubkey,  // Same client pubkey for secret
        claim_request.encryption_nonce,  // Same nonce
        claim_request.encrypted_secret,
    );

    // Set sign PDA bump
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

    // Import the callback from lib.rs
    use crate::pow_privacy::VerifyAndClaimCallback;

    // Custom accounts must match VerifyAndClaimCallback struct order exactly:
    // 1. privacy_config (mut)
    // 2. privacy_authority
    // 3. mint
    // 4. shared_token_vault (mut)
    // 5. destination_token_account (mut)
    // 6. token_program
    // 7. claim (mut)
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        None,
        vec![VerifyAndClaimCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.privacy_config.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.privacy_authority.key(),
                    is_writable: false,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.mint.key(),
                    is_writable: false,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.shared_token_vault.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.destination_token_account.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.token_program.key(),
                    is_writable: false,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.claim.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,  // num_callback_txs
        0,  // cu_price_micro
    )?;

    emit!(MpcComputationQueued {
        computation_type: "verify_and_claim".to_string(),
        timestamp: now,
    });

    Ok(())
}

#[queue_computation_accounts("verify_and_claim", claimer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct ClaimReward<'info> {
    /// Anyone can trigger a claim (doesn't reveal miner identity)
    #[account(mut)]
    pub claimer: Signer<'info>,

    /// Privacy protocol configuration (Boxed to reduce stack)
    #[account(
        mut,
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Box<Account<'info, PrivacyConfig>>,

    /// Claim request buffer containing encrypted claim data
    #[account(
        mut,
        seeds = [CLAIM_REQUEST_BUFFER_SEED, claimer.key().as_ref(), &claim_request_buffer.claim_id.to_le_bytes()],
        bump = claim_request_buffer.bump,
        constraint = !claim_request_buffer.is_used @ ErrorCode::BufferAlreadyUsed,
    )]
    pub claim_request_buffer: Box<Account<'info, ClaimRequestBuffer>>,

    /// Privacy authority PDA
    /// CHECK: PDA verified by seeds
    #[account(
        seeds = [PRIVACY_AUTHORITY_SEED, privacy_config.key().as_ref()],
        bump = privacy_config.authority_bump,
    )]
    pub privacy_authority: UncheckedAccount<'info>,

    /// The claim being processed (Boxed to reduce stack)
    #[account(
        mut,
        seeds = [CLAIM_SEED, privacy_config.key().as_ref(), &claim_request_buffer.claim_id.to_le_bytes()],
        bump = claim.bump,
        constraint = claim.id == claim_request_buffer.claim_id @ ErrorCode::ClaimNotFound,
        constraint = !claim.is_claimed @ ErrorCode::ClaimAlreadyProcessed,
    )]
    pub claim: Box<Account<'info, Claim>>,

    /// Token mint
    pub mint: InterfaceAccount<'info, Mint>,

    /// Shared token vault (Boxed to reduce stack)
    #[account(
        mut,
        seeds = [SHARED_TOKEN_VAULT_SEED, privacy_config.key().as_ref(), mint.key().as_ref()],
        bump = privacy_config.token_vault_bump,
        token::mint = mint,
        token::authority = privacy_authority,
    )]
    pub shared_token_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Destination token account (from claim buffer or provided by claimer)
    #[account(
        mut,
        token::mint = mint,
    )]
    pub destination_token_account: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,

    // === Arcium MPC accounts (using Box to reduce stack usage) ===

    /// Arcium sign PDA account (Boxed to reduce stack)
    #[account(
        init_if_needed,
        space = 9,
        payer = claimer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Box<Account<'info, ArciumSignerAccount>>,

    /// MXE Account
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,

    /// Mempool account
    #[account(
        mut,
        address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: mempool_account, checked by the arcium program
    pub mempool_account: UncheckedAccount<'info>,

    /// Executing pool
    #[account(
        mut,
        address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: executing_pool, checked by the arcium program
    pub executing_pool: UncheckedAccount<'info>,

    /// Computation account
    #[account(
        mut,
        address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet)
    )]
    /// CHECK: computation_account, checked by the arcium program
    pub computation_account: UncheckedAccount<'info>,

    /// Computation definition account for verify_and_claim
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_VERIFY_AND_CLAIM))]
    pub comp_def_account: Box<Account<'info, ComputationDefinitionAccount>>,

    /// Cluster account
    #[account(
        mut,
        address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet)
    )]
    pub cluster_account: Box<Account<'info, Cluster>>,

    /// Arcium fee pool account
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Box<Account<'info, FeePool>>,

    /// Arcium clock account
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Box<Account<'info, ClockAccount>>,

    /// Arcium program
    pub arcium_program: Program<'info, Arcium>,
}
