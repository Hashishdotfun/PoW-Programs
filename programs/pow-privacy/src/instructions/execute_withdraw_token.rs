use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;

/// Build and invoke a transfer_checked instruction with transfer hook accounts.
/// Token-2022 transfer_checked with a hook needs the extra accounts appended
/// in a specific order that matches the ExtraAccountMetaList on-chain.
fn invoke_transfer_checked_with_hook<'info>(
    token_program: &AccountInfo<'info>,
    source: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    destination: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    // Hook accounts in order:
    hook_program: &AccountInfo<'info>,
    extra_account_meta_list: &AccountInfo<'info>,
    hook_fee_vault: &AccountInfo<'info>,
    hook_pow_config: &AccountInfo<'info>,
    pow_protocol_program: &AccountInfo<'info>,
    amount: u64,
    decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};

    // Build transfer_checked instruction data:
    // TokenInstruction::TransferChecked = 12
    // data = [12, amount (8 bytes LE), decimals (1 byte)]
    let mut data = Vec::with_capacity(10);
    data.push(12u8); // TransferChecked
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);

    // Standard transfer_checked accounts
    let mut account_metas = vec![
        AccountMeta::new(source.key(), false),
        AccountMeta::new_readonly(mint.key(), false),
        AccountMeta::new(destination.key(), false),
        AccountMeta::new_readonly(authority.key(), true),
    ];

    // Transfer hook extra accounts (appended after standard accounts)
    // Order must match ExtraAccountMetaList:
    // 1. hook_program (executable, not writable)
    // 2. extra_account_meta_list (not writable)
    // 3. fee_vault (writable) - extra account from meta list
    // 4. pow_config (writable) - extra account from meta list
    // 5. token_program (not writable) - extra account from meta list
    // 6. pow_protocol_program (not writable) - extra account from meta list
    account_metas.push(AccountMeta::new_readonly(hook_program.key(), false));
    account_metas.push(AccountMeta::new_readonly(extra_account_meta_list.key(), false));
    account_metas.push(AccountMeta::new(hook_fee_vault.key(), false));
    account_metas.push(AccountMeta::new(hook_pow_config.key(), false));
    account_metas.push(AccountMeta::new_readonly(token_program.key(), false));
    account_metas.push(AccountMeta::new_readonly(pow_protocol_program.key(), false));

    let ix = Instruction {
        program_id: token_program.key(),
        accounts: account_metas,
        data,
    };

    let account_infos = &[
        source.clone(),
        mint.clone(),
        destination.clone(),
        authority.clone(),
        hook_program.clone(),
        extra_account_meta_list.clone(),
        hook_fee_vault.clone(),
        hook_pow_config.clone(),
        token_program.clone(),
        pow_protocol_program.clone(),
    ];

    invoke_signed(&ix, account_infos, signer_seeds)?;
    Ok(())
}

/// Execute the token transfer after MPC callback has approved the withdrawal.
/// This is step 3 of the HASHISH token withdrawal process:
/// 1. create_withdraw_token_buffer (user creates buffer with encrypted data)
/// 2. withdraw_token_private (queue MPC) → callback marks buffer approved
/// 3. execute_withdraw_token (this instruction does the actual transfers)
pub fn handler(ctx: Context<ExecuteWithdrawToken>) -> Result<()> {
    let buffer = &ctx.accounts.withdraw_token_buffer;

    // Verify buffer was approved by MPC callback
    require!(buffer.is_used, ErrorCode::TokenBufferAlreadyUsed);
    require!(buffer.is_approved, ErrorCode::WithdrawNotApproved);
    require!(!buffer.is_executed, ErrorCode::WithdrawAlreadyExecuted);

    let gross_amount = buffer.verified_amount;

    // Calculate fee (0.5% = 50 bps)
    let fee_bps = ctx.accounts.privacy_config.withdrawal_fee_bps as u64;
    let fee_amount = gross_amount
        .checked_mul(fee_bps)
        .and_then(|v| v.checked_div(BPS_DENOMINATOR))
        .ok_or(ErrorCode::FeeCalculationOverflow)?;
    let net_amount = gross_amount
        .checked_sub(fee_amount)
        .ok_or(ErrorCode::FeeCalculationOverflow)?;

    // PDA signer seeds for privacy_authority
    let config_key = ctx.accounts.privacy_config.key();
    let authority_bump = ctx.accounts.privacy_config.authority_bump;
    let authority_seeds: &[&[u8]] = &[
        PRIVACY_AUTHORITY_SEED,
        config_key.as_ref(),
        &[authority_bump],
    ];
    let signer_seeds: &[&[&[u8]]] = &[authority_seeds];

    // Transfer net amount to destination
    if net_amount > 0 {
        invoke_transfer_checked_with_hook(
            &ctx.accounts.token_program.to_account_info(),
            &ctx.accounts.shared_token_vault.to_account_info(),
            &ctx.accounts.mint.to_account_info(),
            &ctx.accounts.destination_token_account.to_account_info(),
            &ctx.accounts.privacy_authority.to_account_info(),
            &ctx.accounts.transfer_hook_program.to_account_info(),
            &ctx.accounts.extra_account_meta_list.to_account_info(),
            &ctx.accounts.hook_fee_vault.to_account_info(),
            &ctx.accounts.hook_pow_config.to_account_info(),
            &ctx.accounts.pow_protocol_program.to_account_info(),
            net_amount,
            ctx.accounts.mint.decimals,
            signer_seeds,
        )?;
    }

    // Transfer fee to team token account
    if fee_amount > 0 && ctx.accounts.team_token_account.key() != Pubkey::default() {
        invoke_transfer_checked_with_hook(
            &ctx.accounts.token_program.to_account_info(),
            &ctx.accounts.shared_token_vault.to_account_info(),
            &ctx.accounts.mint.to_account_info(),
            &ctx.accounts.team_token_account.to_account_info(),
            &ctx.accounts.privacy_authority.to_account_info(),
            &ctx.accounts.transfer_hook_program.to_account_info(),
            &ctx.accounts.extra_account_meta_list.to_account_info(),
            &ctx.accounts.hook_fee_vault.to_account_info(),
            &ctx.accounts.hook_pow_config.to_account_info(),
            &ctx.accounts.pow_protocol_program.to_account_info(),
            fee_amount,
            ctx.accounts.mint.decimals,
            signer_seeds,
        )?;
    }

    // Mark as executed
    ctx.accounts.withdraw_token_buffer.is_executed = true;

    emit!(TokenWithdrawProcessed {
        gross_amount,
        fee_amount,
        net_amount,
        destination: ctx.accounts.destination_token_account.key(),
        timestamp: Clock::get()?.unix_timestamp,
    });

    msg!(
        "Execute withdraw token: {} tokens net ({} fee) sent to {}",
        net_amount,
        fee_amount,
        ctx.accounts.destination_token_account.key()
    );
    Ok(())
}

#[derive(Accounts)]
pub struct ExecuteWithdrawToken<'info> {
    /// Anyone can execute (relayer or miner)
    #[account(mut)]
    pub caller: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Box<Account<'info, PrivacyConfig>>,

    /// Withdraw token buffer (must be approved by MPC callback)
    #[account(
        mut,
        constraint = withdraw_token_buffer.is_approved @ ErrorCode::WithdrawNotApproved,
        constraint = !withdraw_token_buffer.is_executed @ ErrorCode::WithdrawAlreadyExecuted,
    )]
    pub withdraw_token_buffer: Box<Account<'info, WithdrawTokenBuffer>>,

    /// Privacy authority PDA (signs token transfers)
    /// CHECK: PDA verified by seeds
    #[account(
        seeds = [PRIVACY_AUTHORITY_SEED, privacy_config.key().as_ref()],
        bump = privacy_config.authority_bump,
    )]
    pub privacy_authority: UncheckedAccount<'info>,

    /// Token mint
    pub mint: InterfaceAccount<'info, Mint>,

    /// Shared token vault (HASHISH source for withdrawal)
    #[account(
        mut,
        seeds = [SHARED_TOKEN_VAULT_SEED, privacy_config.key().as_ref(), mint.key().as_ref()],
        bump = privacy_config.token_vault_bump,
        token::mint = mint,
        token::authority = privacy_authority,
    )]
    pub shared_token_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Destination token account for the withdrawal
    #[account(mut)]
    pub destination_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Team token account for receiving withdrawal fees
    #[account(
        mut,
        constraint = team_token_account.key() == privacy_config.team_token_account @ ErrorCode::TeamWalletNotConfigured,
    )]
    pub team_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    pub token_program: Interface<'info, TokenInterface>,

    // === Transfer hook accounts ===

    /// CHECK: Transfer hook program for HASHISH
    pub transfer_hook_program: UncheckedAccount<'info>,

    /// CHECK: Validated by transfer hook
    pub extra_account_meta_list: UncheckedAccount<'info>,

    /// CHECK: Validated by transfer hook
    #[account(mut)]
    pub hook_fee_vault: UncheckedAccount<'info>,

    /// CHECK: Validated by transfer hook
    #[account(mut)]
    pub hook_pow_config: UncheckedAccount<'info>,

    /// CHECK: Program ID
    pub pow_protocol_program: UncheckedAccount<'info>,
}
