use anchor_lang::prelude::*;
use solana_program::hash::hash;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;
use anchor_lang::system_program;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;
// Import ID, ID_CONST, and ArciumSignerAccount for Arcium macros
use crate::{ID, ID_CONST, ArciumSignerAccount};

use pow_protocol::state::{MinerStats, PowConfig};

// Computation definition offset for store_claim
const COMP_DEF_OFFSET_STORE_CLAIM: u32 = comp_def_offset("store_claim");

/// Build the ArgBuilder for store_claim MPC computation
/// Uses 4 encrypted u64 values for the destination pubkey (32 bytes total)
#[inline(never)]
fn build_store_claim_args(
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    encrypted_dest: &[[u8; 32]; 4],  // 4 ciphertexts (one per u64)
) -> ArgumentList {
    ArgBuilder::new()
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_dest[0])
        .encrypted_u64(encrypted_dest[1])
        .encrypted_u64(encrypted_dest[2])
        .encrypted_u64(encrypted_dest[3])
        .build()
}

/// Submit a block via the privacy layer with Arcium MPC (Transaction 2)
///
/// Flow:
/// 1. Miner calls create_claim_buffer with encrypted data (Transaction 1)
/// 2. Relayer receives (nonce, buffer_pda) from miner
/// 3. Relayer calls this instruction (Transaction 2)
/// 4. Reads encrypted data from buffer
/// 5. CPI to pow-protocol::submit_proof (privacy_authority signs)
/// 6. Queue Arcium MPC computation to store encrypted claim
/// 7. Miner can claim later by providing the secret
///
/// Privacy properties:
/// - The destination is encrypted with Arcium x25519 (MPC decryption only)
/// - The secret_hash links miner to claim without revealing identity
pub fn handler(
    ctx: Context<SubmitBlockPrivate>,
    computation_offset: u64,
    nonce: u128,
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let config = &ctx.accounts.privacy_config;
    let pow_config = &ctx.accounts.pow_config;

    // Read encrypted data from the claim buffer
    let claim_buffer = &ctx.accounts.claim_buffer;

    // Verify buffer hasn't been used
    require!(
        !claim_buffer.is_used,
        ErrorCode::ClaimBufferAlreadyUsed
    );

    // Verify encrypted_claim has exactly 4 × 32 = 128 bytes (4 ciphertexts for [u64; 4])
    require!(
        claim_buffer.encrypted_claim_bytes.len() == 4 * 32,
        ErrorCode::InvalidEncryptedData
    );

    // Extract metadata from buffer
    let client_pubkey = claim_buffer.client_pubkey;
    let encryption_nonce = claim_buffer.encryption_nonce;
    let secret_hash = claim_buffer.secret_hash;

    // Extract the 4 encrypted u64 ciphertexts from the buffer
    let encrypted_dest: [[u8; 32]; 4] = [
        claim_buffer.encrypted_claim_bytes[0..32].try_into().unwrap(),
        claim_buffer.encrypted_claim_bytes[32..64].try_into().unwrap(),
        claim_buffer.encrypted_claim_bytes[64..96].try_into().unwrap(),
        claim_buffer.encrypted_claim_bytes[96..128].try_into().unwrap(),
    ];

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Verify caller is the authorized relayer
    require!(
        ctx.accounts.relayer.key() == config.relayer,
        ErrorCode::Unauthorized
    );

    // Verify max claims not reached
    require!(
        config.next_claim_id < MAX_PENDING_CLAIMS,
        ErrorCode::MaxPendingClaimsReached
    );

    // Verify the PoW is valid
    // The hash uses privacy_authority as the "miner" pubkey
    let difficulty = pow_config.difficulty;
    let target = u128::MAX
        .checked_div(difficulty.max(1))
        .ok_or(ErrorCode::DivisionByZero)?;

    let privacy_authority_key = ctx.accounts.privacy_authority.key();
    let mut message = Vec::with_capacity(88);
    message.extend_from_slice(&pow_config.current_challenge);
    message.extend_from_slice(privacy_authority_key.as_ref());
    message.extend_from_slice(&nonce.to_le_bytes());
    message.extend_from_slice(&pow_config.blocks_mined.to_le_bytes());

    let hash_result = hash(&message);
    let hash_bytes = hash_result.to_bytes();
    let hash_value = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());

    require!(hash_value < target, ErrorCode::InvalidProofOfWork);

    // Check fee vault has enough SOL for protocol fee (and rent if needed)
    let protocol_fee = pow_config.fee_sol_current;
    let fee_vault_lamports = ctx.accounts.shared_fee_vault.lamports();
    let mut required_lamports = protocol_fee;
    if ctx.accounts.privacy_miner_stats.data_is_empty() {
        let rent = Rent::get()?.minimum_balance(MinerStats::LEN);
        required_lamports = required_lamports.saturating_add(rent);
    }
    require!(
        fee_vault_lamports >= required_lamports,
        ErrorCode::InsufficientFeeBalance
    );

    // Transfer SOL from fee_vault to privacy_authority for protocol fee (+ rent if needed)
    let config_key = ctx.accounts.privacy_config.key();
    let authority_lamports = ctx.accounts.privacy_authority.lamports();
    let top_up = required_lamports.saturating_sub(authority_lamports);
    if top_up > 0 {
    let fee_vault_bump = [config.fee_vault_bump];
    let fee_vault_seeds: &[&[u8]] = &[
        SHARED_FEE_VAULT_SEED,
        config_key.as_ref(),
        &fee_vault_bump,
    ];
    let fee_vault_signer_seeds: &[&[&[u8]]] = &[fee_vault_seeds];
    let transfer_ctx = CpiContext::new_with_signer(
        ctx.accounts.system_program.to_account_info(),
        system_program::Transfer {
            from: ctx.accounts.shared_fee_vault.to_account_info(),
            to: ctx.accounts.privacy_authority.to_account_info(),
        },
        fee_vault_signer_seeds,
    );
        system_program::transfer(transfer_ctx, top_up)?;
    }

    // Record vault balance before CPI
    let vault_balance_before = ctx.accounts.shared_token_vault.amount;

    // CPI to pow-protocol::submit_proof
    let authority_bump = [config.authority_bump];
    let authority_seeds: &[&[u8]] = &[
        PRIVACY_AUTHORITY_SEED,
        config_key.as_ref(),
        &authority_bump,
    ];
    let authority_signer_seeds: &[&[&[u8]]] = &[authority_seeds];

    let mut ix_data = Vec::with_capacity(24);
    ix_data.extend_from_slice(&SUBMIT_PROOF_DISCRIMINATOR);
    ix_data.extend_from_slice(&nonce.to_le_bytes());

    let cpi_accounts = vec![
        AccountMeta::new(ctx.accounts.privacy_authority.key(), true),
        AccountMeta::new(ctx.accounts.pow_config.key(), false),
        AccountMeta::new(ctx.accounts.mint.key(), false),
        AccountMeta::new(ctx.accounts.shared_token_vault.key(), false),
        AccountMeta::new(ctx.accounts.privacy_miner_stats.key(), false),
        AccountMeta::new(ctx.accounts.pow_fee_collector.key(), false),
        AccountMeta::new_readonly(ctx.accounts.token_program.key(), false),
        AccountMeta::new_readonly(ctx.accounts.system_program.key(), false),
    ];

    let cpi_ix = Instruction {
        program_id: ctx.accounts.pow_program.key(),
        accounts: cpi_accounts,
        data: ix_data,
    };

    invoke_signed(
        &cpi_ix,
        &[
            ctx.accounts.privacy_authority.to_account_info(),
            ctx.accounts.pow_config.to_account_info(),
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.shared_token_vault.to_account_info(),
            ctx.accounts.privacy_miner_stats.to_account_info(),
            ctx.accounts.pow_fee_collector.to_account_info(),
            ctx.accounts.token_program.to_account_info(),
            ctx.accounts.system_program.to_account_info(),
        ],
        authority_signer_seeds,
    )?;

    // Reload vault to get new balance
    ctx.accounts.shared_token_vault.reload()?;
    let vault_balance_after = ctx.accounts.shared_token_vault.amount;
    let reward_amount = vault_balance_after.saturating_sub(vault_balance_before);

    // Capture claim_id before mutable borrows
    let claim_id = config.next_claim_id;
    let block_number = pow_config.blocks_mined;

    // Queue Arcium MPC computation for store_claim first (before mutable borrows)
    // This stores the encrypted destination securely in MPC
    // Uses 4 encrypted u64 values (4 ciphertexts total)
    let args = build_store_claim_args(client_pubkey, encryption_nonce, &encrypted_dest);

    // Set sign PDA bump
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

    // Import the callback from lib.rs
    use crate::pow_privacy::StoreClaimCallback;

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        None,
        vec![StoreClaimCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[CallbackAccount {
                pubkey: ctx.accounts.privacy_config.key(),
                is_writable: true,
            }],
        )?],
        1,  // num_callback_txs
        0,  // cu_price_micro
    )?;

    // Now initialize the claim account (after queue_computation)
    let claim = &mut ctx.accounts.claim;
    claim.id = claim_id;
    claim.amount = reward_amount;
    // Copy encrypted bytes from the buffer
    claim.encrypted_destination = ctx.accounts.claim_buffer.encrypted_claim_bytes.clone();
    claim.client_pubkey = client_pubkey;
    claim.encryption_nonce = encryption_nonce;
    claim.secret_hash = secret_hash;
    claim.is_claimed = false;
    claim.verification_pending = true; // MPC is pending
    claim.block_number = block_number;
    claim.created_at = now;
    claim.claimed_at = 0;
    claim.bump = ctx.bumps.claim;

    // Update config
    let config = &mut ctx.accounts.privacy_config;
    config.next_claim_id += 1;
    config.total_claims += 1;
    config.total_blocks += 1;

    emit!(BlockSubmittedPrivate {
        claim_id,
        amount: reward_amount,
        block_number,
        timestamp: now,
    });

    emit!(MpcComputationQueued {
        computation_type: "store_claim".to_string(),
        timestamp: now,
    });

    // Mark the buffer as used
    let claim_buffer = &mut ctx.accounts.claim_buffer;
    claim_buffer.is_used = true;

    emit!(ClaimBufferConsumed {
        buffer: claim_buffer.key(),
        claim_id,
        timestamp: now,
    });

    Ok(())
}

#[queue_computation_accounts("store_claim", relayer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct SubmitBlockPrivate<'info> {
    /// The relayer (authorized to submit blocks)
    #[account(mut)]
    pub relayer: Signer<'info>,

    /// Privacy protocol configuration (Boxed to reduce stack)
    #[account(
        mut,
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
        constraint = privacy_config.relayer == relayer.key() @ ErrorCode::Unauthorized,
    )]
    pub privacy_config: Box<Account<'info, PrivacyConfig>>,

    /// Claim buffer containing encrypted data (created in Transaction 1)
    #[account(
        mut,
        seeds = [CLAIM_BUFFER_SEED, claim_buffer.owner.as_ref(), &claim_buffer.secret_hash],
        bump = claim_buffer.bump,
        constraint = !claim_buffer.is_used @ ErrorCode::ClaimBufferAlreadyUsed,
    )]
    pub claim_buffer: Box<Account<'info, ClaimBuffer>>,

    /// Privacy authority PDA (the "miner" for pow-protocol)
    /// CHECK: PDA verified by seeds
    #[account(
        mut,
        seeds = [PRIVACY_AUTHORITY_SEED, privacy_config.key().as_ref()],
        bump = privacy_config.authority_bump,
    )]
    pub privacy_authority: UncheckedAccount<'info>,

    /// Claim account to store the encrypted claim (Boxed to reduce stack)
    #[account(
        init,
        payer = relayer,
        space = Claim::LEN,
        seeds = [CLAIM_SEED, privacy_config.key().as_ref(), &privacy_config.next_claim_id.to_le_bytes()],
        bump,
    )]
    pub claim: Box<Account<'info, Claim>>,

    /// Shared token vault (receives minted rewards) - Boxed to reduce stack
    #[account(
        mut,
        seeds = [SHARED_TOKEN_VAULT_SEED, privacy_config.key().as_ref(), mint.key().as_ref()],
        bump = privacy_config.token_vault_bump,
        token::mint = mint,
        token::authority = privacy_authority,
    )]
    pub shared_token_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Shared fee vault (pays protocol fee)
    /// CHECK: PDA verified by seeds
    #[account(
        mut,
        seeds = [SHARED_FEE_VAULT_SEED, privacy_config.key().as_ref()],
        bump = privacy_config.fee_vault_bump,
    )]
    pub shared_fee_vault: UncheckedAccount<'info>,

    // === pow-protocol accounts for CPI (using Box for large accounts) ===

    /// PowConfig from main protocol
    #[account(mut)]
    pub pow_config: Box<Account<'info, PowConfig>>,

    /// Token mint
    #[account(mut)]
    pub mint: InterfaceAccount<'info, Mint>,

    /// MinerStats for privacy_authority in pow-protocol
    /// CHECK: Created/validated by pow-protocol during CPI
    #[account(mut)]
    pub privacy_miner_stats: UncheckedAccount<'info>,

    /// Fee collector in pow-protocol
    /// CHECK: PDA of pow-protocol, validated during CPI
    #[account(mut)]
    pub pow_fee_collector: UncheckedAccount<'info>,

    /// The pow-protocol program
    /// CHECK: Verified by constraint
    #[account(constraint = pow_program.key() == pow_protocol::ID @ ErrorCode::InvalidProgram)]
    pub pow_program: UncheckedAccount<'info>,

    pub token_program: Interface<'info, TokenInterface>,
    pub system_program: Program<'info, System>,

    // === Arcium MPC accounts (using Box to reduce stack usage) ===

    /// Arcium sign PDA account
    #[account(
        init_if_needed,
        space = 9,
        payer = relayer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,

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

    /// Computation definition account for store_claim
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_STORE_CLAIM))]
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
