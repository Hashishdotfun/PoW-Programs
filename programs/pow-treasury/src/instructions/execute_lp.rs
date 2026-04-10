// =============================================================================
// INSTRUCTION: EXECUTE LP CYCLE
// =============================================================================
// Phase B du cycle treasury:
// 1. Wrap SOL → wSOL
// 2. CPI Meteora DAMM v2 add_liquidity
// 3. LP position → PDA du protocole (locked forever)
// 4. Payer reward au cranker
// 5. Si pas assez de SOL → ajouter ce qu'on peut, excédent tokens carry over

use anchor_lang::prelude::*;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface, SyncNative, sync_native};

use crate::constants::*;
use crate::errors::TreasuryError;
use crate::state::{TreasuryConfig, CycleGate};
use crate::meteora_cpi;

/// Compute liquidity_delta from token amounts and pool reserves.
///
/// For DAMM v2: liquidity_delta = min(amount_a * total_liq / reserve_a, amount_b * total_liq / reserve_b)
/// Uses 256-bit intermediate math to avoid u128 overflow.
fn compute_liquidity_delta_from_reserves(
    amount_a: u64,
    amount_b: u64,
    reserve_a: u64,
    reserve_b: u64,
    total_liquidity: u128,
) -> u128 {
    if reserve_a == 0 || reserve_b == 0 || total_liquidity == 0 {
        return (amount_a as u128) * (amount_b as u128);
    }

    // Use U256 math: amount * total_liq can overflow u128
    // Split into: (amount * (total_liq / reserve)) + (amount * (total_liq % reserve)) / reserve
    let delta_a = mul_div_u128(amount_a as u128, total_liquidity, reserve_a as u128);
    let delta_b = mul_div_u128(amount_b as u128, total_liquidity, reserve_b as u128);

    delta_a.min(delta_b)
}

/// Compute (a * b) / c without overflow using 256-bit intermediate.
/// Splits b = (b/c)*c + (b%c) to keep intermediate products in u128 range.
fn mul_div_u128(a: u128, b: u128, c: u128) -> u128 {
    if c == 0 { return 0; }

    let quotient = b / c;
    let remainder = b % c;

    // a * quotient won't overflow if a is u64-range and quotient fits
    // But to be safe, use checked_mul with fallback to iterative approach
    let part1 = match a.checked_mul(quotient) {
        Some(v) => v,
        None => {
            // a * quotient overflows u128 — result is huge, cap at u128::MAX
            return u128::MAX;
        }
    };

    let part2 = match a.checked_mul(remainder) {
        Some(v) => v / c,
        None => {
            // a * remainder overflows — split further: a = a_hi * c + a_lo
            let a_q = a / c;
            let a_r = a % c;
            a_q * remainder + a_r * remainder / c
        }
    };

    part1.saturating_add(part2)
}

/// Exécute le cycle d'ajout de liquidité (Phase B)
///
/// Permissionless avec incentive cranker.
/// Utilise les tokens du buyback (phase A) + SOL frais pour ajouter
/// de la liquidité dans le pool Meteora DAMM v2.
/// La position LP est détenue par le PDA treasury (locked forever).
pub fn handler<'info>(
    ctx: Context<'_, '_, '_, 'info, ExecuteLpCycle<'info>>,
) -> Result<()> {
    let config = &ctx.accounts.treasury_config;

    // Vérifications
    require!(config.is_enabled, TreasuryError::CycleDisabled);
    require!(config.current_phase == PHASE_LP, TreasuryError::WrongPhase);
    require!(config.tokens_for_lp > 0, TreasuryError::InsufficientTokens);

    // Vérifier le CycleGate — un nouveau cycle doit être autorisé par pow-protocol
    let cycle_gate_data = CycleGate::try_deserialize(
        &mut &ctx.accounts.cycle_gate.data.borrow()[..]
    )?;
    require!(
        cycle_gate_data.cycle_number > config.last_consumed_cycle,
        TreasuryError::CycleNotReady
    );

    // SOL disponible
    let sol_vault = &ctx.accounts.treasury_sol_vault;
    let rent = Rent::get()?;
    let min_balance = rent.minimum_balance(0);
    let available_sol = sol_vault.lamports().saturating_sub(min_balance);

    // Cranker reward
    let cranker_reward = if available_sol > 0 {
        (available_sol
            .checked_mul(CRANKER_REWARD_BPS)
            .ok_or(TreasuryError::Overflow)?
            / 10_000)
            .max(CRANKER_MIN_REWARD)
            .min(available_sol / 10)
    } else {
        0
    };

    // Only wrap LP_SOL_WRAP_PCT% of fresh SOL — rest stays for next buyback
    let sol_after_cranker = available_sol.saturating_sub(cranker_reward);
    let sol_for_lp = sol_after_cranker
        .checked_mul(LP_SOL_WRAP_PCT)
        .ok_or(TreasuryError::Overflow)?
        / 100;

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
    // 2. WRAP SOL → wSOL (si on a du SOL)
    // =========================================================================

    if sol_for_lp > 0 {
        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.treasury_sol_vault.to_account_info(),
                    to: ctx.accounts.wsol_vault.to_account_info(),
                },
                sol_vault_seeds,
            ),
            sol_for_lp,
        )?;

        sync_native(
            CpiContext::new_with_signer(
                ctx.accounts.token_program_standard.to_account_info(),
                SyncNative {
                    account: ctx.accounts.wsol_vault.to_account_info(),
                },
                config_seeds,
            ),
        )?;

        msg!("Wrapped {} lamports to wSOL for LP", sol_for_lp);
    }

    // =========================================================================
    // 3. VERIFY LP POSITION EXISTS
    // =========================================================================

    require!(
        ctx.accounts.treasury_config.lp_position != Pubkey::default(),
        TreasuryError::PositionNotInitialized
    );
    require!(
        ctx.accounts.position.key() == ctx.accounts.treasury_config.lp_position,
        TreasuryError::InvalidPosition
    );
    msg!("Adding to existing position: {}", ctx.accounts.position.key());

    // =========================================================================
    // 4. CPI METEORA DAMM v2 ADD LIQUIDITY
    // =========================================================================

    // Read pool vault balances to compute correct liquidity_delta
    let vault_a_balance = {
        let data = ctx.accounts.token_a_vault.try_borrow_data()?;
        require!(data.len() >= 72, TreasuryError::InvalidPool);
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    };
    let vault_b_balance = {
        let data = ctx.accounts.token_b_vault.try_borrow_data()?;
        require!(data.len() >= 72, TreasuryError::InvalidPool);
        u64::from_le_bytes(data[64..72].try_into().unwrap())
    };

    // Read total permanent locked liquidity from pool account
    let pool_total_liquidity = {
        let data = ctx.accounts.damm_pool.try_borrow_data()?;
        if data.len() >= 376 {
            u128::from_le_bytes(data[360..376].try_into().unwrap())
        } else {
            0u128
        }
    };

    msg!("Pool reserves: vault_a={}, vault_b={}, total_liq={}", vault_a_balance, vault_b_balance, pool_total_liquidity);

    // Use ACTUAL vault balances (includes accumulated excess from previous cycles)
    // Reload wsol_vault after wrapping to get real balance
    ctx.accounts.wsol_vault.reload()?;
    let actual_wsol = ctx.accounts.wsol_vault.amount;
    let actual_tokens = ctx.accounts.treasury_token_vault.amount;

    msg!("Vault balances: wSOL={}, HASHISH={}", actual_wsol, actual_tokens);

    // Determine token ordering and use actual vault balances as max amounts
    let wsol_mint_key = ctx.accounts.wsol_mint.key();
    let (token_a_amount, token_b_amount, reserve_a, reserve_b) = if ctx.accounts.token_a_mint.key() == wsol_mint_key {
        (actual_wsol, actual_tokens, vault_a_balance, vault_b_balance)
    } else {
        (actual_tokens, actual_wsol, vault_b_balance, vault_a_balance)
    };

    let liquidity_delta = compute_liquidity_delta_from_reserves(
        token_a_amount,
        token_b_amount,
        reserve_a,
        reserve_b,
        pool_total_liquidity,
    );

    require!(liquidity_delta > 0, TreasuryError::InsufficientTokens);

    // Build token account references matching pool ordering
    let (token_a_account, token_b_account, token_a_program, token_b_program) =
        if ctx.accounts.token_a_mint.key() == wsol_mint_key {
            (
                ctx.accounts.wsol_vault.to_account_info(),
                ctx.accounts.treasury_token_vault.to_account_info(),
                ctx.accounts.token_program_standard.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
            )
        } else {
            (
                ctx.accounts.treasury_token_vault.to_account_info(),
                ctx.accounts.wsol_vault.to_account_info(),
                ctx.accounts.token_program.to_account_info(),
                ctx.accounts.token_program_standard.to_account_info(),
            )
        };

    meteora_cpi::add_liquidity(
        meteora_cpi::AddLiquidityAccounts {
            pool: ctx.accounts.damm_pool.to_account_info(),
            position: ctx.accounts.position.to_account_info(),
            token_a_account,
            token_b_account,
            token_a_vault: ctx.accounts.token_a_vault.to_account_info(),
            token_b_vault: ctx.accounts.token_b_vault.to_account_info(),
            token_a_mint: ctx.accounts.token_a_mint.to_account_info(),
            token_b_mint: ctx.accounts.token_b_mint.to_account_info(),
            position_nft_account: ctx.accounts.position_nft_account.to_account_info(),
            owner: ctx.accounts.treasury_config.to_account_info(),
            token_a_program,
            token_b_program,
            event_authority: ctx.accounts.event_authority.to_account_info(),
            damm_program: ctx.accounts.damm_program.to_account_info(),
        },
        liquidity_delta,
        token_a_amount,
        token_b_amount,
        config_seeds,
    )?;

    // Compute actual amounts consumed by checking vault balances after add_liquidity
    ctx.accounts.wsol_vault.reload()?;
    ctx.accounts.treasury_token_vault.reload()?;
    let wsol_used = actual_wsol.saturating_sub(ctx.accounts.wsol_vault.amount);
    let tokens_used = actual_tokens.saturating_sub(ctx.accounts.treasury_token_vault.amount);

    msg!("Liquidity added: {} wSOL + {} HASHISH", wsol_used, tokens_used);

    // =========================================================================
    // 5. PERMANENT LOCK ALL UNLOCKED LIQUIDITY
    // =========================================================================
    {
        let position_data = ctx.accounts.position.try_borrow_data()?;
        let unlocked_liquidity = if position_data.len() >= 168 {
            u128::from_le_bytes(position_data[152..168].try_into().unwrap())
        } else {
            0
        };
        drop(position_data);

        if unlocked_liquidity > 0 {
            meteora_cpi::permanent_lock_position(
                meteora_cpi::PermanentLockPositionAccounts {
                    pool: ctx.accounts.damm_pool.to_account_info(),
                    position: ctx.accounts.position.to_account_info(),
                    position_nft_account: ctx.accounts.position_nft_account.to_account_info(),
                    owner: ctx.accounts.treasury_config.to_account_info(),
                    event_authority: ctx.accounts.event_authority.to_account_info(),
                    damm_program: ctx.accounts.damm_program.to_account_info(),
                },
                unlocked_liquidity,
                config_seeds,
            )?;
            msg!("Permanently locked {} liquidity units", unlocked_liquidity);
        }
    }

    // =========================================================================
    // 6. METTRE À JOUR LE STATE
    // =========================================================================

    let config = &mut ctx.accounts.treasury_config;

    config.total_tokens_to_lp = config.total_tokens_to_lp
        .checked_add(tokens_used)
        .ok_or(TreasuryError::Overflow)?;
    config.total_sol_to_lp = config.total_sol_to_lp
        .checked_add(wsol_used)
        .ok_or(TreasuryError::Overflow)?;
    config.total_cranker_rewards = config.total_cranker_rewards
        .checked_add(cranker_reward)
        .ok_or(TreasuryError::Overflow)?;

    // Only zero out tokens_for_lp if all were consumed, otherwise keep the remainder
    let tokens_remaining = actual_tokens.saturating_sub(tokens_used);
    config.tokens_for_lp = tokens_remaining;

    // Consommer le cycle et avancer la phase
    config.last_consumed_cycle = cycle_gate_data.cycle_number;
    config.current_phase = PHASE_BUYBACK;
    config.total_cycles = config.total_cycles
        .checked_add(1)
        .ok_or(TreasuryError::Overflow)?;
    config.cycle_attempts = 0;
    config.last_cycle_ts = Clock::get()?.unix_timestamp;

    msg!("LP cycle complete:");
    msg!("  Tokens used: {}", tokens_used);
    msg!("  SOL used: {} lamports", wsol_used);
    msg!("  Tokens remaining: {}", tokens_remaining);
    msg!("  Total cycles: {}", config.total_cycles);
    msg!("  Phase → Buyback (A)");

    Ok(())
}

#[derive(Accounts)]
pub struct ExecuteLpCycle<'info> {
    /// Cranker qui trigger le cycle (reçoit la reward)
    #[account(mut)]
    pub cranker: Signer<'info>,

    /// Treasury config
    #[account(
        mut,
        seeds = [TREASURY_CONFIG_SEED],
        bump = treasury_config.bump,
    )]
    pub treasury_config: Account<'info, TreasuryConfig>,

    /// CycleGate PDA from pow-protocol (read-only, cross-program)
    /// CHECK: Validated by seed derivation against pow-protocol program ID
    #[account(
        seeds = [CYCLE_GATE_SEED],
        bump,
        seeds::program = treasury_config.pow_protocol,
    )]
    pub cycle_gate: AccountInfo<'info>,

    /// Treasury SOL vault
    /// CHECK: PDA du treasury
    #[account(
        mut,
        seeds = [TREASURY_SOL_VAULT_SEED],
        bump,
    )]
    pub treasury_sol_vault: AccountInfo<'info>,

    /// wSOL vault
    #[account(
        mut,
        token::authority = treasury_config,
        seeds = [TREASURY_WSOL_VAULT_SEED],
        bump,
    )]
    pub wsol_vault: InterfaceAccount<'info, TokenAccount>,

    /// Treasury token vault (source des tokens HASHISH)
    #[account(
        mut,
        token::authority = treasury_config,
        token::token_program = token_program,
        seeds = [TREASURY_TOKEN_VAULT_SEED],
        bump,
    )]
    pub treasury_token_vault: InterfaceAccount<'info, TokenAccount>,

    /// wSOL mint
    pub wsol_mint: InterfaceAccount<'info, Mint>,

    // =========================================================================
    // COMPTES METEORA DAMM v2
    // =========================================================================

    /// Position LP existante (stockée dans treasury_config.lp_position)
    /// CHECK: Validé par contrainte treasury_config.lp_position dans le handler
    #[account(mut)]
    pub position: AccountInfo<'info>,

    /// Position NFT token account (prouve la détention de la position)
    /// CHECK: Compte Meteora
    pub position_nft_account: AccountInfo<'info>,

    /// Pool Meteora DAMM v2
    /// CHECK: Validé par contrainte
    #[account(
        mut,
        constraint = damm_pool.key() == treasury_config.damm_pool @ TreasuryError::InvalidPool,
    )]
    pub damm_pool: AccountInfo<'info>,

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

    /// Event authority (PDA de Meteora)
    /// CHECK: Compte Meteora
    pub event_authority: AccountInfo<'info>,

    /// Meteora DAMM v2 program
    /// CHECK: Programme Meteora
    pub damm_program: AccountInfo<'info>,

    /// Token program standard (SPL Token, pour wSOL)
    /// CHECK: SPL Token program
    pub token_program_standard: AccountInfo<'info>,

    /// Token program (SPL Token 2022, pour HASHISH)
    pub token_program: Interface<'info, TokenInterface>,

    pub system_program: Program<'info, System>,
}
