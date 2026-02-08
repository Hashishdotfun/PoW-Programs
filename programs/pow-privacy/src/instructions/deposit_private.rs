use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;
use crate::{ID, ID_CONST, ArciumSignerAccount};

// Computation definition offset for deposit_fee
const COMP_DEF_OFFSET_DEPOSIT_FEE: u32 = comp_def_offset("deposit_fee");

/// Build the ArgBuilder for deposit_fee MPC computation
/// Circuit signature: deposit_fee(amount, current_state) -> (MinerState, DepositFeeResult)
/// Input 1: Encrypted amount (1 ciphertext for Enc<Shared, u64>)
/// Input 2: Encrypted current_state (3 ciphertexts for MinerState: balance, nonce, reserved)
/// Note: current_state is Arcium persistent state - initialized to zeros for new miners
#[inline(never)]
fn build_deposit_fee_args(
    client_pubkey: [u8; 32],
    encryption_nonce: u128,
    encrypted_amount: [u8; 32],
    encrypted_current_state: [[u8; 32]; 3],
) -> ArgumentList {
    ArgBuilder::new()
        // Input 1: encrypted amount (1 x u64)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_amount)
        // Input 2: encrypted current_state (3 x u64: balance, nonce, reserved)
        .x25519_pubkey(client_pubkey)
        .plaintext_u128(encryption_nonce)
        .encrypted_u64(encrypted_current_state[0])
        .encrypted_u64(encrypted_current_state[1])
        .encrypted_u64(encrypted_current_state[2])
        .build()
}

/// Execute deposit with MPC balance update
/// This is step 2 of the deposit process
///
/// Flow:
/// 1. Verify deposit buffer exists and is unused
/// 2. Transfer SOL from depositor to shared vault
/// 3. Queue Arcium MPC computation to update encrypted balance
/// 4. MPC callback marks buffer as used
pub fn handler(ctx: Context<DepositPrivate>, computation_offset: u64) -> Result<()> {
    let config = &ctx.accounts.privacy_config;
    let buffer = &ctx.accounts.deposit_buffer;
    let clock = Clock::get()?;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Verify buffer is not already used
    require!(!buffer.is_used, ErrorCode::BufferAlreadyUsed);

    // Transfer SOL from depositor to shared fee vault
    transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: ctx.accounts.depositor.to_account_info(),
                to: ctx.accounts.shared_fee_vault.to_account_info(),
            },
        ),
        buffer.amount,
    )?;

    let new_balance = ctx.accounts.shared_fee_vault.lamports();

    // Build MPC arguments from the deposit buffer
    let args = build_deposit_fee_args(
        buffer.client_pubkey,
        buffer.encryption_nonce,
        buffer.encrypted_amount,
        buffer.encrypted_current_state,
    );

    // Set sign PDA bump
    ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

    // Import the callback from lib.rs
    use crate::pow_privacy::DepositFeeCallback;

    // Custom accounts must match DepositFeeCallback struct order exactly:
    // 1. privacy_config (mut)
    // 2. deposit_buffer (mut)
    queue_computation(
        ctx.accounts,
        computation_offset,
        args,
        vec![DepositFeeCallback::callback_ix(
            computation_offset,
            &ctx.accounts.mxe_account,
            &[
                CallbackAccount {
                    pubkey: ctx.accounts.privacy_config.key(),
                    is_writable: true,
                },
                CallbackAccount {
                    pubkey: ctx.accounts.deposit_buffer.key(),
                    is_writable: true,
                },
            ],
        )?],
        1,  // num_callback_txs
        0,  // cu_price_micro
    )?;

    emit!(DepositProcessed {
        amount: buffer.amount,
        timestamp: clock.unix_timestamp,
    });

    emit!(FeeDeposited {
        amount: buffer.amount,
        new_balance,
    });

    emit!(MpcComputationQueued {
        computation_type: "deposit_fee".to_string(),
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}

#[queue_computation_accounts("deposit_fee", depositor)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct DepositPrivate<'info> {
    /// Depositor who created the buffer and funds the deposit
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        mut,
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Box<Account<'info, PrivacyConfig>>,

    /// Deposit buffer with encrypted data
    #[account(
        mut,
        has_one = owner @ ErrorCode::InvalidOwner,
        constraint = !deposit_buffer.is_used @ ErrorCode::BufferAlreadyUsed,
    )]
    pub deposit_buffer: Box<Account<'info, DepositBuffer>>,

    /// Owner must match depositor
    /// CHECK: Verified via has_one
    #[account(address = depositor.key())]
    pub owner: AccountInfo<'info>,

    /// Shared fee vault
    /// CHECK: PDA verified by seeds
    #[account(
        mut,
        seeds = [SHARED_FEE_VAULT_SEED, privacy_config.key().as_ref()],
        bump = privacy_config.fee_vault_bump,
    )]
    pub shared_fee_vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,

    // === Arcium MPC accounts ===

    /// Arcium sign PDA account
    #[account(
        init_if_needed,
        space = 9,
        payer = depositor,
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

    /// Computation definition account for deposit_fee
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_DEPOSIT_FEE))]
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
