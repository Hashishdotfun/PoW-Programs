// =============================================================================
// INSTRUCTION: EXECUTE BUYBACK CYCLE
// =============================================================================
// Phase A du cycle treasury:
// 1. Wrap SOL → wSOL
// 2. CPI swap Meteora DAMM v2 wSOL→HASHISH
// 3. Burn 50% des tokens reçus
// 4. Garder 50% pour LP (phase B)
// 5. Payer reward au cranker

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, Burn, burn, SyncNative, sync_native};

use crate::constants::*;
use crate::errors::TreasuryError;
use crate::state::{TreasuryConfig, CycleGate};
use crate::meteora_cpi;

/// Compute min_amount_out from on-chain pool vault balances (x*y=k).
///
/// DAMM v2 is a constant product AMM:
///   amount_out = reserve_out * amount_in / (reserve_in + amount_in)
///   min_amount_out = amount_out * (10000 - max_slippage_bps) / 10000
fn compute_min_amount_out(
    swap_amount: u64,
    reserve_in: u64,
    reserve_out: u64,
    max_slippage_bps: u16,
) -> Result<u64> {
    // Avoid division by zero
    if reserve_in == 0 || reserve_out == 0 {
        return Ok(0);
    }

    // expected_out = reserve_out * swap_amount / (reserve_in + swap_amount)
    let numerator = (reserve_out as u128)
        .checked_mul(swap_amount as u128)
        .ok_or(TreasuryError::Overflow)?;
    let denominator = (reserve_in as u128)
        .checked_add(swap_amount as u128)
        .ok_or(TreasuryError::Overflow)?;
    let expected_out = numerator / denominator;

    // Apply slippage: min_out = expected * (10000 - slippage) / 10000
    let slippage_factor = 10000u128.saturating_sub(max_slippage_bps as u128);
    let min_out = expected_out * slippage_factor / 10000u128;

    let min_amount_out = if min_out > u64::MAX as u128 {
        u64::MAX
    } else {
        min_out as u64
    };

    msg!("Slippage guard: reserve_in={}, reserve_out={}, expected={}, min_out={} ({}bps slippage)",
        reserve_in, reserve_out, expected_out, min_amount_out, max_slippage_bps);

    Ok(min_amount_out)
}

/// Exécute le cycle de buyback (Phase A)
///
/// Permissionless avec incentive cranker.
/// 1. Wrap SOL → wSOL dans le wsol_vault
/// 2. CPI swap Meteora DAMM v2 wSOL→HASHISH
/// 3. Burn 50% des tokens reçus
/// 4. Stocke 50% pour le cycle LP
/// 5. Paye reward au cranker
pub fn handler<'info>(ctx: Context<'_, '_, '_, 'info, ExecuteBuybackCycle<'info>>) -> Result<()> {
    let config = &ctx.accounts.treasury_config;

    // Vérifications
    require!(config.is_enabled, TreasuryError::CycleDisabled);

    // Vérifier le CycleGate — un nouveau cycle (mega ou super-mega) doit être autorisé
    // Le buyback consomme la Phase A. Le LP suivra dans une 2e tx (Phase B).
    let cycle_gate_data = CycleGate::try_deserialize(
        &mut &ctx.accounts.cycle_gate.data.borrow()[..]
    )?;
    require!(
        cycle_gate_data.cycle_number > config.last_consumed_buyback_cycle,
        TreasuryError::CycleNotReady
    );

    // SOL disponible (total accumulé depuis le dernier mega)
    let sol_vault = &ctx.accounts.treasury_sol_vault;
    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(0);
    let available_sol = sol_vault.lamports().saturating_sub(min_balance);

    require!(available_sol > 0, TreasuryError::InsufficientSol);

    // Buyback consomme BUYBACK_SOL_PCT% du SOL total disponible.
    // Le reste (~34%) est laissé dans le vault pour la Phase B (LP) du même cycle.
    let buyback_budget = available_sol
        .checked_mul(BUYBACK_SOL_PCT)
        .ok_or(TreasuryError::Overflow)?
        / 100;
    require!(buyback_budget > 0, TreasuryError::InsufficientSol);

    // Cranker reward calculé sur le budget buyback (0.1%, min 5000 lamports, max 10%)
    let cranker_reward = (buyback_budget
        .checked_mul(CRANKER_REWARD_BPS)
        .ok_or(TreasuryError::Overflow)?
        / 10_000)
        .max(CRANKER_MIN_REWARD)
        .min(buyback_budget / 10);

    let swap_amount = buyback_budget.saturating_sub(cranker_reward);
    require!(swap_amount > 0, TreasuryError::InsufficientSol);

    let sol_vault_bump = ctx.bumps.treasury_sol_vault;
    let sol_vault_seeds: &[&[&[u8]]] = &[&[
        TREASURY_SOL_VAULT_SEED,
        &[sol_vault_bump],
    ]];

    let config_bump = ctx.accounts.treasury_config.bump;
    let config_seeds: &[&[&[u8]]] = &[&[
        TREASURY_CONFIG_SEED,
        &[config_bump],
    ]];

    // =========================================================================
    // 1. PAYER LE CRANKER
    // =========================================================================

    if cranker_reward > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.treasury_sol_vault.to_account_info(),
                    to: ctx.accounts.cranker.to_account_info(),
                },
                sol_vault_seeds,
            ),
            cranker_reward,
        )?;
        msg!("Cranker reward: {} lamports", cranker_reward);
    }

    // =========================================================================
    // 2. WRAP SOL → wSOL
    // =========================================================================

    // Transfer lamports from sol_vault to wsol_vault
    anchor_lang::system_program::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.treasury_sol_vault.to_account_info(),
                to: ctx.accounts.wsol_vault.to_account_info(),
            },
            sol_vault_seeds,
        ),
        swap_amount,
    )?;

    // Sync native to update wSOL balance
    sync_native(
        CpiContext::new_with_signer(
            ctx.accounts.token_program_standard.to_account_info(),
            SyncNative {
                account: ctx.accounts.wsol_vault.to_account_info(),
            },
            config_seeds,
        ),
    )?;

    msg!("Wrapped {} lamports to wSOL", swap_amount);

    // =========================================================================
    // 3. CPI SWAP METEORA DAMM v2 (wSOL → HASHISH)
    // =========================================================================

    // Record token balance before swap
    let token_balance_before = ctx.accounts.treasury_token_vault.amount;

    // =========================================================================
    // SLIPPAGE PROTECTION: compute min_amount_out from vault balances (x*y=k)
    // =========================================================================
    // Read vault balances to compute expected output
    let vault_a_balance = {
        let data = ctx.accounts.token_a_vault.try_borrow_data()?;
        // SPL Token account: amount is at offset 64 (8 bytes, little-endian)
        require!(data.len() >= 72, TreasuryError::InvalidPool);
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    };
    let vault_b_balance = {
        let data = ctx.accounts.token_b_vault.try_borrow_data()?;
        require!(data.len() >= 72, TreasuryError::InvalidPool);
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    };

    // Determine swap direction: we swap wSOL for HASHISH
    // token_a could be wSOL or HASHISH depending on pool ordering
    // We check by comparing mint keys
    let wsol_mint_key = ctx.accounts.wsol_mint.key();
    let (reserve_in, reserve_out) = if ctx.accounts.token_a_mint.key() == wsol_mint_key {
        (vault_a_balance, vault_b_balance)
    } else {
        (vault_b_balance, vault_a_balance)
    };

    let min_amount_out = compute_min_amount_out(
        swap_amount,
        reserve_in,
        reserve_out,
        config.max_slippage_bps,
    )?;

    meteora_cpi::swap(
        meteora_cpi::SwapAccounts {
            pool_authority: ctx.accounts.pool_authority.to_account_info(),
            pool: ctx.accounts.damm_pool.to_account_info(),
            input_token_account: ctx.accounts.wsol_vault.to_account_info(),
            output_token_account: ctx.accounts.treasury_token_vault.to_account_info(),
            token_a_vault: ctx.accounts.token_a_vault.to_account_info(),
            token_b_vault: ctx.accounts.token_b_vault.to_account_info(),
            token_a_mint: ctx.accounts.token_a_mint.to_account_info(),
            token_b_mint: ctx.accounts.token_b_mint.to_account_info(),
            payer: ctx.accounts.treasury_config.to_account_info(),
            token_a_program: ctx.accounts.token_program_standard.to_account_info(),
            token_b_program: ctx.accounts.token_program.to_account_info(),
            referral_token_account: ctx.accounts.damm_program.to_account_info(),
            event_authority: ctx.accounts.event_authority.to_account_info(),
            damm_program: ctx.accounts.damm_program.to_account_info(),
        },
        swap_amount,
        min_amount_out,
        config_seeds,
    )?;

    // Reload token vault to get updated balance
    ctx.accounts.treasury_token_vault.reload()?;
    let token_balance_after = ctx.accounts.treasury_token_vault.amount;
    let tokens_received = token_balance_after.saturating_sub(token_balance_before);

    msg!("Swap complete: {} lamports → {} tokens", swap_amount, tokens_received);

    require!(tokens_received > 0, TreasuryError::SwapFailed);

    // =========================================================================
    // 4. BURN 50% DES TOKENS
    // =========================================================================

    let burn_amount = tokens_received / 2;
    let lp_amount = tokens_received.saturating_sub(burn_amount);

    if burn_amount > 0 {
        burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint: ctx.accounts.mint.to_account_info(),
                    from: ctx.accounts.treasury_token_vault.to_account_info(),
                    authority: ctx.accounts.treasury_config.to_account_info(),
                },
                config_seeds,
            ),
            burn_amount,
        )?;

        // CPI → pow-protocol::record_treasury_burn to free supply cap
        let cpi_program = ctx.accounts.pow_program.to_account_info();
        let cpi_accounts = pow_protocol::cpi::accounts::RecordTreasuryBurn {
            caller: ctx.accounts.treasury_config.to_account_info(),
            pow_config_normal: ctx.accounts.pow_config_normal.to_account_info(),
            pow_config_seeker: ctx.accounts.pow_config_seeker.to_account_info(),
        };
        pow_protocol::cpi::record_treasury_burn(
            CpiContext::new_with_signer(cpi_program, cpi_accounts, config_seeds),
            burn_amount,
        )?;

        msg!("Burned {} tokens, supply cap freed", burn_amount);
    }

    // =========================================================================
    // 5. METTRE À JOUR LE STATE
    // =========================================================================

    let config = &mut ctx.accounts.treasury_config;
    config.tokens_for_lp = config.tokens_for_lp
        .checked_add(lp_amount)
        .ok_or(TreasuryError::Overflow)?;
    config.total_sol_swapped = config.total_sol_swapped
        .checked_add(swap_amount)
        .ok_or(TreasuryError::Overflow)?;
    config.total_tokens_burned = config.total_tokens_burned
        .checked_add(burn_amount)
        .ok_or(TreasuryError::Overflow)?;
    config.total_cranker_rewards = config.total_cranker_rewards
        .checked_add(cranker_reward)
        .ok_or(TreasuryError::Overflow)?;

    // Consommer la phase A pour ce cycle
    config.last_consumed_buyback_cycle = cycle_gate_data.cycle_number;
    config.cycle_attempts = 0;
    config.last_cycle_ts = Clock::get()?.unix_timestamp;

    msg!("Buyback (Phase A) complete (cycle #{}):", cycle_gate_data.cycle_number);
    msg!("  SOL swapped: {} lamports", swap_amount);
    msg!("  Tokens received: {}", tokens_received);
    msg!("  Tokens burned: {}", burn_amount);
    msg!("  Tokens for LP: {}", lp_amount);
    msg!("  Next: cranker should now call execute_lp for the same cycle");

    Ok(())
}

#[derive(Accounts)]
pub struct ExecuteBuybackCycle<'info> {
    /// Cranker qui trigger le cycle (reçoit la reward)
    #[account(mut)]
    pub cranker: Signer<'info>,

    /// Treasury config
    #[account(
        mut,
        seeds = [TREASURY_CONFIG_SEED],
        bump = treasury_config.bump,
    )]
    pub treasury_config: Box<Account<'info, TreasuryConfig>>,

    /// CycleGate PDA from pow-protocol (read-only, cross-program)
    /// CHECK: Validated by seed derivation against pow-protocol program ID stored in treasury_config
    #[account(
        seeds = [CYCLE_GATE_SEED],
        bump,
        seeds::program = treasury_config.pow_protocol,
    )]
    pub cycle_gate: AccountInfo<'info>,

    /// Treasury SOL vault (source SOL natif)
    /// CHECK: PDA du treasury
    #[account(
        mut,
        seeds = [TREASURY_SOL_VAULT_SEED],
        bump,
    )]
    pub treasury_sol_vault: AccountInfo<'info>,

    /// wSOL vault (pour wrapping avant swap)
    #[account(
        mut,
        token::authority = treasury_config,
        seeds = [TREASURY_WSOL_VAULT_SEED],
        bump,
    )]
    pub wsol_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// Treasury token vault (destination des tokens HASHISH achetés)
    #[account(
        mut,
        token::mint = mint,
        token::authority = treasury_config,
        token::token_program = token_program,
        seeds = [TREASURY_TOKEN_VAULT_SEED],
        bump,
    )]
    pub treasury_token_vault: Box<InterfaceAccount<'info, TokenAccount>>,

    /// HASHISH mint (SPL2022, pour le burn)
    #[account(
        mut,
        constraint = mint.key() == treasury_config.mint,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    /// wSOL mint
    pub wsol_mint: Box<InterfaceAccount<'info, Mint>>,

    // =========================================================================
    // COMPTES METEORA DAMM v2
    // =========================================================================

    /// Meteora DAMM v2 pool
    /// CHECK: Validé par contrainte sur treasury_config
    #[account(
        mut,
        constraint = damm_pool.key() == treasury_config.damm_pool @ TreasuryError::InvalidPool,
    )]
    pub damm_pool: AccountInfo<'info>,

    /// DAMM v2 pool authority (constant PDA)
    /// CHECK: Compte Meteora
    pub pool_authority: AccountInfo<'info>,

    /// Pool token A vault
    /// CHECK: Compte Meteora
    #[account(mut)]
    pub token_a_vault: AccountInfo<'info>,

    /// Pool token B vault
    /// CHECK: Compte Meteora
    #[account(mut)]
    pub token_b_vault: AccountInfo<'info>,

    /// Token A mint
    /// CHECK: Compte Meteora
    pub token_a_mint: AccountInfo<'info>,

    /// Token B mint
    /// CHECK: Compte Meteora
    pub token_b_mint: AccountInfo<'info>,

    /// Meteora DAMM v2 program
    /// CHECK: Validated by known program ID
    pub damm_program: AccountInfo<'info>,

    /// Event authority (PDA de Meteora)
    /// CHECK: Compte Meteora
    pub event_authority: AccountInfo<'info>,

    /// Token program standard (SPL Token, pour wSOL)
    /// CHECK: SPL Token program
    pub token_program_standard: AccountInfo<'info>,

    /// Token program (SPL Token 2022, pour HASHISH)
    pub token_program: Interface<'info, TokenInterface>,

    pub system_program: Program<'info, System>,

    // =========================================================================
    // COMPTES POW-PROTOCOL (pour record_treasury_burn CPI)
    // =========================================================================

    /// Programme pow-protocol
    /// CHECK: Validated by treasury_config.pow_protocol
    #[account(
        constraint = pow_program.key() == treasury_config.pow_protocol @ TreasuryError::InvalidPool,
    )]
    pub pow_program: AccountInfo<'info>,

    /// PoW Config normal (pool 0)
    /// CHECK: PDA du programme pow-protocol, validé par le CPI
    #[account(mut)]
    pub pow_config_normal: AccountInfo<'info>,

    /// PoW Config seeker (pool 1)
    /// CHECK: PDA du programme pow-protocol, validé par le CPI
    #[account(mut)]
    pub pow_config_seeker: AccountInfo<'info>,
}
