// =============================================================================
// INSTRUCTION: COLLECT TRANSFER FEES
// =============================================================================
// Remplace le transfer-hook pour la collecte des fees SPL2022 TransferFeeConfig.
//
// Permissionless (cranker incentive). Fait tout en une seule instruction :
// 1. Harvest: collecte les withheld fees des token accounts → mint
// 2. Withdraw: retire les fees du mint → fee_token_vault PDA
// 3. Burn 50% des tokens collectés (permanent deflation)
// 4. Ajoute 50% aux pending_reward_tokens (distribué aux mineurs)
// 5. Mint cranker reward
//
// Le fee_authority PDA est le withdrawWithheldAuthority du mint.
// remaining_accounts: token accounts sources à harvest (writable)

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::constants::*;
use crate::errors::PowError;
use crate::state::PowConfig;

/// Seed for the fee_authority PDA (= withdrawWithheldAuthority on the mint)
pub const FEE_AUTHORITY_SEED: &[u8] = b"fee_authority";

/// Seed for the fee token vault PDA (holds withdrawn fees before burn/distribute)
pub const FEE_TOKEN_VAULT_SEED: &[u8] = b"fee_token_vault";

/// Cranker reward: 0.1% of collected fees (in basis points)
const CRANKER_FEE_BPS: u64 = 10;

/// Burn share: 49.95% (after cranker cut)
/// Miner share: 49.95% (after cranker cut)
/// Total: cranker 0.1% + burn 49.95% + miners 49.95% = 100%
const BURN_PERCENT: u64 = 50;

/// Collect and distribute SPL2022 transfer fees.
///
/// Permissionless with cranker incentive.
/// 1. Harvest withheld fees from token accounts passed as remaining_accounts
/// 2. Withdraw fees from mint to fee_token_vault
/// 3. Burn 50%, add 50% to pending miner rewards
/// 4. Mint cranker reward (1% of total)
pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, CollectTransferFees<'info>>,
) -> Result<()> {
    let mint_key = ctx.accounts.mint.key();
    let fee_auth_bump = ctx.bumps.fee_authority;
    let fee_auth_seeds: &[&[&[u8]]] = &[&[
        FEE_AUTHORITY_SEED,
        mint_key.as_ref(),
        &[fee_auth_bump],
    ]];

    // =========================================================================
    // 1. HARVEST: withheld fees from source accounts → mint
    // =========================================================================
    let sources = ctx.remaining_accounts;
    if !sources.is_empty() {
        // HarvestWithheldTokensToMint: TokenInstruction::TransferFeeExtension = 26, sub = 4
        let data = vec![26u8, 4u8];

        let mut account_metas = vec![
            AccountMeta::new(ctx.accounts.mint.key(), false),
        ];
        for source in sources.iter() {
            account_metas.push(AccountMeta::new(source.key(), false));
        }

        let ix = Instruction {
            program_id: ctx.accounts.token_program.key(),
            accounts: account_metas,
            data,
        };

        let mut account_infos = vec![ctx.accounts.mint.to_account_info()];
        for source in sources.iter() {
            account_infos.push(source.clone());
        }

        // Permissionless — no signer needed for harvest
        invoke_signed(&ix, &account_infos, &[])?;

        msg!("Harvested withheld fees from {} accounts", sources.len());
    }

    // =========================================================================
    // 2. WITHDRAW: from mint → fee_token_vault (fee_authority PDA = withdraw authority)
    // =========================================================================
    // WithdrawWithheldTokensFromMint: instruction=26, sub=2
    // Accounts: [mint (writable), destination (writable), authority (signer)]
    {
        let data = vec![26u8, 2u8];

        let account_metas = vec![
            AccountMeta::new(ctx.accounts.mint.key(), false),
            AccountMeta::new(ctx.accounts.fee_token_vault.key(), false),
            AccountMeta::new_readonly(ctx.accounts.fee_authority.key(), true),
        ];

        let ix = Instruction {
            program_id: ctx.accounts.token_program.key(),
            accounts: account_metas,
            data,
        };

        let account_infos = vec![
            ctx.accounts.mint.to_account_info(),
            ctx.accounts.fee_token_vault.to_account_info(),
            ctx.accounts.fee_authority.to_account_info(),
        ];

        invoke_signed(&ix, &account_infos, fee_auth_seeds)?;

        msg!("Withdrew withheld fees from mint to fee_token_vault");
    }

    // =========================================================================
    // 3. DISTRIBUTE: burn 50% + pending reward 50% + cranker reward
    // =========================================================================
    ctx.accounts.fee_token_vault.reload()?;
    let current_balance = ctx.accounts.fee_token_vault.amount;

    if current_balance == 0 {
        msg!("No fees to distribute");
        return Ok(());
    }

    // Cranker reward (1% of total fees)
    let cranker_reward = current_balance
        .checked_mul(CRANKER_FEE_BPS)
        .ok_or(PowError::Overflow)?
        / 10_000;

    let distributable = current_balance.saturating_sub(cranker_reward);

    let burn_share = distributable
        .checked_mul(BURN_PERCENT)
        .ok_or(PowError::Overflow)?
        / 100;

    let miner_share = distributable.saturating_sub(burn_share);

    msg!("Distributing {} tokens: cranker={}, burn={}, miners={}",
        current_balance, cranker_reward, burn_share, miner_share);

    let fee_vault_bump = ctx.bumps.fee_token_vault;
    let fee_vault_seeds: &[&[&[u8]]] = &[&[
        FEE_TOKEN_VAULT_SEED,
        mint_key.as_ref(),
        &[fee_vault_bump],
    ]];

    // Transfer cranker reward from vault to cranker's token account
    if cranker_reward > 0 {
        anchor_spl::token_interface::transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token_interface::TransferChecked {
                    from: ctx.accounts.fee_token_vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.cranker_token_account.to_account_info(),
                    authority: ctx.accounts.fee_token_vault.to_account_info(),
                },
                fee_vault_seeds,
            ),
            cranker_reward,
            ctx.accounts.mint.decimals,
        )?;
        msg!("Cranker reward: {} tokens transferred", cranker_reward);
    }

    // Burn the burn_share
    if burn_share > 0 {
        anchor_spl::token_interface::burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                anchor_spl::token_interface::Burn {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.fee_token_vault.to_account_info(),
                    authority: ctx.accounts.fee_token_vault.to_account_info(),
                },
                fee_vault_seeds,
            ),
            burn_share,
        )?;

        // Record burn as permanent deflation (free supply cap)
        let normal_share = burn_share / 2;
        let seeker_share = burn_share.saturating_sub(normal_share);

        let config_normal = &mut ctx.accounts.pow_config_normal;
        config_normal.total_burned_from_transfer_tax = config_normal
            .total_burned_from_transfer_tax
            .checked_add(normal_share)
            .ok_or(PowError::Overflow)?;
        config_normal.total_supply_mined = config_normal
            .total_supply_mined
            .saturating_sub(normal_share);

        let config_seeker = &mut ctx.accounts.pow_config_seeker;
        config_seeker.total_burned_from_transfer_tax = config_seeker
            .total_burned_from_transfer_tax
            .checked_add(seeker_share)
            .ok_or(PowError::Overflow)?;
        config_seeker.total_supply_mined = config_seeker
            .total_supply_mined
            .saturating_sub(seeker_share);

        msg!("Burned {} tokens (supply cap freed)", burn_share);
    }

    // Add miner share to pending rewards (tokens stay in fee_token_vault)
    if miner_share > 0 {
        let normal_share = miner_share / 2;
        let seeker_share = miner_share.saturating_sub(normal_share);

        let config_normal = &mut ctx.accounts.pow_config_normal;
        config_normal.pending_reward_tokens = config_normal
            .pending_reward_tokens
            .checked_add(normal_share)
            .ok_or(PowError::Overflow)?;

        let config_seeker = &mut ctx.accounts.pow_config_seeker;
        config_seeker.pending_reward_tokens = config_seeker
            .pending_reward_tokens
            .checked_add(seeker_share)
            .ok_or(PowError::Overflow)?;

        msg!("Added {} tokens to miner pending rewards", miner_share);
    }

    msg!("Fee collection complete!");

    Ok(())
}

// =============================================================================
// ACCOUNTS
// =============================================================================

#[derive(Accounts)]
pub struct CollectTransferFees<'info> {
    /// Cranker (anyone can call, receives token reward)
    #[account(mut)]
    pub cranker: Signer<'info>,

    /// Token mint (SPL2022 with TransferFeeConfig)
    #[account(
        mut,
        constraint = mint.key() == pow_config_normal.mint @ PowError::InvalidMint,
    )]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Fee authority PDA — this is the withdrawWithheldAuthority on the mint.
    /// Seeds: ["fee_authority", mint]
    /// CHECK: PDA verified by seeds
    #[account(
        seeds = [FEE_AUTHORITY_SEED, mint.key().as_ref()],
        bump,
    )]
    pub fee_authority: AccountInfo<'info>,

    /// Fee token vault — holds withdrawn fees before burn/distribute.
    /// Authority is itself (PDA).
    /// Seeds: ["fee_token_vault", mint]
    #[account(
        mut,
        token::mint = mint,
        token::authority = fee_token_vault,
        token::token_program = token_program,
        seeds = [FEE_TOKEN_VAULT_SEED, mint.key().as_ref()],
        bump,
    )]
    pub fee_token_vault: InterfaceAccount<'info, TokenAccount>,

    /// PoW Config normal (pool 0)
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[POOL_NORMAL]],
        bump = pow_config_normal.bump,
    )]
    pub pow_config_normal: Box<Account<'info, PowConfig>>,

    /// PoW Config seeker (pool 1)
    #[account(
        mut,
        seeds = [POW_CONFIG_SEED, &[POOL_SEEKER]],
        bump = pow_config_seeker.bump,
    )]
    pub pow_config_seeker: Box<Account<'info, PowConfig>>,

    /// Cranker's token account (receives the HASHISH reward)
    #[account(
        mut,
        token::mint = mint,
        token::token_program = token_program,
    )]
    pub cranker_token_account: InterfaceAccount<'info, TokenAccount>,

    /// SPL Token 2022 program
    pub token_program: Interface<'info, TokenInterface>,
}
