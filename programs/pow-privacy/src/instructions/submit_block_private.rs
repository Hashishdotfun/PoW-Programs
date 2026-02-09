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

// Computation definition offset for mine_block (verifies balance and deducts fee)
const COMP_DEF_OFFSET_MINE_BLOCK: u32 = comp_def_offset("mine_block");

/// Build the ArgBuilder for mine_block MPC computation
/// Circuit signature: mine_block(protocol_fee, current_state) -> (MinerState, MineBlockResult)
///
/// Arguments (in order matching circuit):
/// 1. protocol_fee: u64 - The fee to deduct from miner's balance (1 ciphertext)
/// 2. current_state: MinerState - Miner's current state: balance, nonce, reserved (3 ciphertexts)
#[inline(never)]
fn build_mine_block_args(
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    protocol_fee: u64,
    encrypted_current_state: &[[u8; 32]; 3],
) -> ArgumentList {
    // Convert protocol_fee to encrypted format
    let fee_bytes: [u8; 32] = {
        let mut arr = [0u8; 32];
        arr[..8].copy_from_slice(&protocol_fee.to_le_bytes());
        arr
    };

    ArgBuilder::new()
        // Arg 1: protocol_fee (1 x u64)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(fee_bytes)
        // Arg 2: current_state (3 x u64 for MinerState: balance, nonce, reserved)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_current_state[0])
        .encrypted_u64(encrypted_current_state[1])
        .encrypted_u64(encrypted_current_state[2])
        .build()
}

/// Submit a block via the privacy layer with Arcium MPC
///
/// Flow:
/// 1. Miner sends encrypted data to relayer off-chain
/// 2. Relayer calls this instruction with all data as parameters
/// 3. Verifies PoW is valid
/// 4. Queues Arcium MPC computation (mine_block) to verify miner balance
/// 5. CPI to pow-protocol::submit_proof (privacy_authority signs)
/// 6. Creates Claim for miner to collect rewards later
///
/// Privacy properties:
/// - The destination is encrypted with Arcium x25519 (MPC decryption only)
/// - The miner's balance is verified in MPC without revealing it
/// - The secret_hash links miner to claim without revealing identity
///
/// # Arguments
/// * `computation_offset` - Arcium computation offset
/// * `nonce` - The PoW nonce found by miner
/// * `client_pubkey` - x25519 public key for Arcium decryption
/// * `encryption_nonce` - Nonce used with RescueCipher
/// * `secret_hash` - SHA256 hash of the claim secret
/// * `encrypted_destination` - Encrypted destination pubkey (4 x 32 bytes)
/// * `encrypted_current_state` - Encrypted miner state (3 x 32 bytes)
pub fn handler(
    ctx: Context<SubmitBlockPrivate>,
    computation_offset: u64,
    nonce: u128,
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    secret_hash: [u8; 32],
    encrypted_destination: [[u8; 32]; 4],
    encrypted_current_state: [[u8; 32]; 3],
) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let config = &ctx.accounts.privacy_config;
    let pow_config = &ctx.accounts.pow_config;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

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
    // Use fixed array instead of Vec to save stack space
    let mut message = [0u8; 88]; // 32 + 32 + 16 + 8 = 88 bytes
    message[..32].copy_from_slice(&pow_config.current_challenge);
    message[32..64].copy_from_slice(privacy_authority_key.as_ref());
    message[64..80].copy_from_slice(&nonce.to_le_bytes());
    message[80..88].copy_from_slice(&pow_config.blocks_mined.to_le_bytes());

    let hash_result = hash(&message);
    let hash_bytes = hash_result.to_bytes();
    let hash_value = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());

    require!(hash_value < target, ErrorCode::InvalidProofOfWork);

    // Get protocol fee from pow_config
    let protocol_fee = pow_config.fee_sol_current;

    // Check fee vault has enough SOL for protocol fee (and rent if needed)
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

    let mut ix_data = [0u8; 24];
    ix_data[..8].copy_from_slice(&SUBMIT_PROOF_DISCRIMINATOR);
    ix_data[8..24].copy_from_slice(&nonce.to_le_bytes());

    let cpi_accounts = [
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
        accounts: cpi_accounts.to_vec(),
        data: ix_data.to_vec(),
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

    // Queue Arcium MPC computation for mine_block
    // This verifies miner has sufficient balance and deducts the protocol fee
    let args = build_mine_block_args(
        client_pubkey,
        encryption_nonce,
        protocol_fee,
        &encrypted_current_state,
    );

    // Set sign PDA bump
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

    // Import the callback from lib.rs
    use crate::pow_privacy::MineBlockCallback;

    // Get claim key before it's initialized (we know the PDA address)
    let claim_key = ctx.accounts.claim.key();

    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![MineBlockCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.privacy_config.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: claim_key,
                    is_writable: true,
                },
            ],
        )?],
        1,  // num_callback_txs
        0,  // cu_price_micro
    )?;

    // Now initialize the claim account
    let claim = &mut ctx.accounts.claim;
    claim.id = claim_id;
    claim.amount = reward_amount;
    // Store encrypted destination as Vec<u8>
    let mut dest_bytes = Vec::with_capacity(128);
    for chunk in &encrypted_destination {
        dest_bytes.extend_from_slice(chunk);
    }
    claim.encrypted_destination = dest_bytes;
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
        computation_type: "mine_block".to_string(),
        timestamp: now,
    });

    Ok(())
}

#[queue_computation_accounts("mine_block", relayer)]
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
    )]
    pub privacy_config: Box<Account<'info, PrivacyConfig>>,

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

    /// Computation definition account for mine_block
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_MINE_BLOCK))]
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
