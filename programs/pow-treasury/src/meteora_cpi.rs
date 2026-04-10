// =============================================================================
// METEORA DAMM v2 RAW CPI HELPERS
// =============================================================================
// Raw CPI vers le programme Meteora DAMM v2 (cp_amm) sans dépendance crate.
// Programme: cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG
//
// DAMM v2 = Constant Product AMM (full range, x*y=k)
// Pas de bins, pas de bin arrays — bien plus simple que DLMM.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::program::invoke_signed;

// =============================================================================
// INSTRUCTION DISCRIMINATORS (from IDL)
// =============================================================================

/// swap discriminator
pub const SWAP_DISCRIMINATOR: [u8; 8] = [248, 198, 158, 145, 225, 117, 135, 200];

/// create_position discriminator
pub const CREATE_POSITION_DISCRIMINATOR: [u8; 8] = [48, 215, 197, 153, 96, 203, 180, 133];

/// add_liquidity discriminator
pub const ADD_LIQUIDITY_DISCRIMINATOR: [u8; 8] = [181, 157, 89, 67, 143, 182, 52, 72];

/// claim_position_fee discriminator
pub const CLAIM_POSITION_FEE_DISCRIMINATOR: [u8; 8] = [180, 38, 154, 17, 133, 33, 162, 211];

/// permanent_lock_position discriminator
pub const PERMANENT_LOCK_POSITION_DISCRIMINATOR: [u8; 8] = [165, 176, 125, 6, 231, 171, 186, 213];

/// DAMM v2 pool_authority (constant PDA)
pub const DAMM_POOL_AUTHORITY: &str = "HLnpSz9h2S4hiLQ43rnSD9XkcUThA7B8hQMKmDaiTLcC";

// =============================================================================
// SWAP CPI
// =============================================================================

pub struct SwapAccounts<'info> {
    pub pool_authority: AccountInfo<'info>,
    pub pool: AccountInfo<'info>,
    pub input_token_account: AccountInfo<'info>,
    pub output_token_account: AccountInfo<'info>,
    pub token_a_vault: AccountInfo<'info>,
    pub token_b_vault: AccountInfo<'info>,
    pub token_a_mint: AccountInfo<'info>,
    pub token_b_mint: AccountInfo<'info>,
    pub payer: AccountInfo<'info>,
    pub token_a_program: AccountInfo<'info>,
    pub token_b_program: AccountInfo<'info>,
    pub referral_token_account: AccountInfo<'info>,
    pub event_authority: AccountInfo<'info>,
    pub damm_program: AccountInfo<'info>,
}

/// Execute Meteora DAMM v2 swap via raw CPI
pub fn swap<'info>(
    accounts: SwapAccounts<'info>,
    amount_in: u64,
    minimum_amount_out: u64,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&SWAP_DISCRIMINATOR);
    // SwapParameters { amount_in: u64, minimum_amount_out: u64 }
    data.extend_from_slice(&amount_in.to_le_bytes());
    data.extend_from_slice(&minimum_amount_out.to_le_bytes());

    let account_metas = vec![
        AccountMeta::new_readonly(accounts.pool_authority.key(), false),
        AccountMeta::new(accounts.pool.key(), false),
        AccountMeta::new(accounts.input_token_account.key(), false),
        AccountMeta::new(accounts.output_token_account.key(), false),
        AccountMeta::new(accounts.token_a_vault.key(), false),
        AccountMeta::new(accounts.token_b_vault.key(), false),
        AccountMeta::new_readonly(accounts.token_a_mint.key(), false),
        AccountMeta::new_readonly(accounts.token_b_mint.key(), false),
        AccountMeta::new_readonly(accounts.payer.key(), true),
        AccountMeta::new_readonly(accounts.token_a_program.key(), false),
        AccountMeta::new_readonly(accounts.token_b_program.key(), false),
        AccountMeta::new_readonly(accounts.referral_token_account.key(), false),
        AccountMeta::new_readonly(accounts.event_authority.key(), false),
        AccountMeta::new_readonly(accounts.damm_program.key(), false),
    ];

    let ix = Instruction {
        program_id: accounts.damm_program.key(),
        accounts: account_metas,
        data,
    };

    let account_infos = vec![
        accounts.pool_authority,
        accounts.pool,
        accounts.input_token_account,
        accounts.output_token_account,
        accounts.token_a_vault,
        accounts.token_b_vault,
        accounts.token_a_mint,
        accounts.token_b_mint,
        accounts.payer,
        accounts.token_a_program,
        accounts.token_b_program,
        accounts.referral_token_account,
        accounts.event_authority,
        accounts.damm_program,
    ];

    invoke_signed(&ix, &account_infos, signer_seeds)?;

    Ok(())
}

// =============================================================================
// CREATE POSITION CPI
// =============================================================================

pub struct CreatePositionAccounts<'info> {
    pub owner: AccountInfo<'info>,
    pub position_nft_mint: AccountInfo<'info>,
    pub position_nft_account: AccountInfo<'info>,
    pub pool: AccountInfo<'info>,
    pub position: AccountInfo<'info>,
    pub pool_authority: AccountInfo<'info>,
    pub payer: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
    pub system_program: AccountInfo<'info>,
    pub event_authority: AccountInfo<'info>,
    pub damm_program: AccountInfo<'info>,
}

/// Create a DAMM v2 position via raw CPI
/// Position is represented by an NFT mint.
pub fn create_position<'info>(
    accounts: CreatePositionAccounts<'info>,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let data = CREATE_POSITION_DISCRIMINATOR.to_vec();

    let account_metas = vec![
        AccountMeta::new_readonly(accounts.owner.key(), false),
        AccountMeta::new(accounts.position_nft_mint.key(), true),  // signer (new keypair)
        AccountMeta::new(accounts.position_nft_account.key(), false),
        AccountMeta::new(accounts.pool.key(), false),
        AccountMeta::new(accounts.position.key(), false),
        AccountMeta::new_readonly(accounts.pool_authority.key(), false),
        AccountMeta::new(accounts.payer.key(), true),
        AccountMeta::new_readonly(accounts.token_program.key(), false),
        AccountMeta::new_readonly(accounts.system_program.key(), false),
        AccountMeta::new_readonly(accounts.event_authority.key(), false),
        AccountMeta::new_readonly(accounts.damm_program.key(), false),
    ];

    let ix = Instruction {
        program_id: accounts.damm_program.key(),
        accounts: account_metas,
        data,
    };

    let account_infos = vec![
        accounts.owner,
        accounts.position_nft_mint,
        accounts.position_nft_account,
        accounts.pool,
        accounts.position,
        accounts.pool_authority,
        accounts.payer,
        accounts.token_program,
        accounts.system_program,
        accounts.event_authority,
        accounts.damm_program,
    ];

    invoke_signed(&ix, &account_infos, signer_seeds)?;

    Ok(())
}

// =============================================================================
// ADD LIQUIDITY CPI
// =============================================================================

pub struct AddLiquidityAccounts<'info> {
    pub pool: AccountInfo<'info>,
    pub position: AccountInfo<'info>,
    pub token_a_account: AccountInfo<'info>,
    pub token_b_account: AccountInfo<'info>,
    pub token_a_vault: AccountInfo<'info>,
    pub token_b_vault: AccountInfo<'info>,
    pub token_a_mint: AccountInfo<'info>,
    pub token_b_mint: AccountInfo<'info>,
    pub position_nft_account: AccountInfo<'info>,
    pub owner: AccountInfo<'info>,
    pub token_a_program: AccountInfo<'info>,
    pub token_b_program: AccountInfo<'info>,
    pub event_authority: AccountInfo<'info>,
    pub damm_program: AccountInfo<'info>,
}

/// Add liquidity to a DAMM v2 position via raw CPI
///
/// # Arguments
/// * `liquidity_delta` - Amount of liquidity to add (u128, Q64 format)
/// * `max_amount_a` - Maximum token A to deposit (slippage protection)
/// * `max_amount_b` - Maximum token B to deposit (slippage protection)
pub fn add_liquidity<'info>(
    accounts: AddLiquidityAccounts<'info>,
    liquidity_delta: u128,
    max_amount_a: u64,
    max_amount_b: u64,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = Vec::with_capacity(40);
    data.extend_from_slice(&ADD_LIQUIDITY_DISCRIMINATOR);
    // AddLiquidityParameters { liquidity_delta: u128, token_a_amount_threshold: u64, token_b_amount_threshold: u64 }
    data.extend_from_slice(&liquidity_delta.to_le_bytes());
    data.extend_from_slice(&max_amount_a.to_le_bytes());
    data.extend_from_slice(&max_amount_b.to_le_bytes());

    let account_metas = vec![
        AccountMeta::new(accounts.pool.key(), false),
        AccountMeta::new(accounts.position.key(), false),
        AccountMeta::new(accounts.token_a_account.key(), false),
        AccountMeta::new(accounts.token_b_account.key(), false),
        AccountMeta::new(accounts.token_a_vault.key(), false),
        AccountMeta::new(accounts.token_b_vault.key(), false),
        AccountMeta::new_readonly(accounts.token_a_mint.key(), false),
        AccountMeta::new_readonly(accounts.token_b_mint.key(), false),
        AccountMeta::new_readonly(accounts.position_nft_account.key(), false),
        AccountMeta::new_readonly(accounts.owner.key(), true),
        AccountMeta::new_readonly(accounts.token_a_program.key(), false),
        AccountMeta::new_readonly(accounts.token_b_program.key(), false),
        AccountMeta::new_readonly(accounts.event_authority.key(), false),
        AccountMeta::new_readonly(accounts.damm_program.key(), false),
    ];

    let ix = Instruction {
        program_id: accounts.damm_program.key(),
        accounts: account_metas,
        data,
    };

    let account_infos = vec![
        accounts.pool,
        accounts.position,
        accounts.token_a_account,
        accounts.token_b_account,
        accounts.token_a_vault,
        accounts.token_b_vault,
        accounts.token_a_mint,
        accounts.token_b_mint,
        accounts.position_nft_account,
        accounts.owner,
        accounts.token_a_program,
        accounts.token_b_program,
        accounts.event_authority,
        accounts.damm_program,
    ];

    invoke_signed(&ix, &account_infos, signer_seeds)?;

    Ok(())
}

// =============================================================================
// CLAIM POSITION FEE CPI
// =============================================================================

pub struct ClaimFeeAccounts<'info> {
    pub pool_authority: AccountInfo<'info>,
    pub pool: AccountInfo<'info>,
    pub position: AccountInfo<'info>,
    pub token_a_account: AccountInfo<'info>,
    pub token_b_account: AccountInfo<'info>,
    pub token_a_vault: AccountInfo<'info>,
    pub token_b_vault: AccountInfo<'info>,
    pub token_a_mint: AccountInfo<'info>,
    pub token_b_mint: AccountInfo<'info>,
    pub position_nft_account: AccountInfo<'info>,
    pub owner: AccountInfo<'info>,
    pub token_a_program: AccountInfo<'info>,
    pub token_b_program: AccountInfo<'info>,
    pub event_authority: AccountInfo<'info>,
    pub damm_program: AccountInfo<'info>,
}

/// Claim fees from a DAMM v2 position via raw CPI
pub fn claim_fee<'info>(
    accounts: ClaimFeeAccounts<'info>,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let data = CLAIM_POSITION_FEE_DISCRIMINATOR.to_vec();

    let account_metas = vec![
        AccountMeta::new_readonly(accounts.pool_authority.key(), false),
        AccountMeta::new_readonly(accounts.pool.key(), false),
        AccountMeta::new(accounts.position.key(), false),
        AccountMeta::new(accounts.token_a_account.key(), false),
        AccountMeta::new(accounts.token_b_account.key(), false),
        AccountMeta::new(accounts.token_a_vault.key(), false),
        AccountMeta::new(accounts.token_b_vault.key(), false),
        AccountMeta::new_readonly(accounts.token_a_mint.key(), false),
        AccountMeta::new_readonly(accounts.token_b_mint.key(), false),
        AccountMeta::new_readonly(accounts.position_nft_account.key(), false),
        AccountMeta::new_readonly(accounts.owner.key(), true),
        AccountMeta::new_readonly(accounts.token_a_program.key(), false),
        AccountMeta::new_readonly(accounts.token_b_program.key(), false),
        AccountMeta::new_readonly(accounts.event_authority.key(), false),
        AccountMeta::new_readonly(accounts.damm_program.key(), false),
    ];

    let ix = Instruction {
        program_id: accounts.damm_program.key(),
        accounts: account_metas,
        data,
    };

    let account_infos = vec![
        accounts.pool_authority,
        accounts.pool,
        accounts.position,
        accounts.token_a_account,
        accounts.token_b_account,
        accounts.token_a_vault,
        accounts.token_b_vault,
        accounts.token_a_mint,
        accounts.token_b_mint,
        accounts.position_nft_account,
        accounts.owner,
        accounts.token_a_program,
        accounts.token_b_program,
        accounts.event_authority,
        accounts.damm_program,
    ];

    invoke_signed(&ix, &account_infos, signer_seeds)?;

    Ok(())
}

// =============================================================================
// PERMANENT LOCK POSITION CPI
// =============================================================================

pub struct PermanentLockPositionAccounts<'info> {
    pub pool: AccountInfo<'info>,
    pub position: AccountInfo<'info>,
    pub position_nft_account: AccountInfo<'info>,
    pub owner: AccountInfo<'info>,
    pub event_authority: AccountInfo<'info>,
    pub damm_program: AccountInfo<'info>,
}

/// Permanently lock liquidity in a DAMM v2 position via raw CPI.
/// This is irreversible — locked liquidity can never be withdrawn.
/// Fees can still be claimed on locked positions.
pub fn permanent_lock_position<'info>(
    accounts: PermanentLockPositionAccounts<'info>,
    permanent_lock_liquidity: u128,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    let mut data = Vec::with_capacity(24);
    data.extend_from_slice(&PERMANENT_LOCK_POSITION_DISCRIMINATOR);
    data.extend_from_slice(&permanent_lock_liquidity.to_le_bytes());

    let account_metas = vec![
        AccountMeta::new(accounts.pool.key(), false),
        AccountMeta::new(accounts.position.key(), false),
        AccountMeta::new_readonly(accounts.position_nft_account.key(), false),
        AccountMeta::new_readonly(accounts.owner.key(), true),
        AccountMeta::new_readonly(accounts.event_authority.key(), false),
        AccountMeta::new_readonly(accounts.damm_program.key(), false),
    ];

    let ix = Instruction {
        program_id: accounts.damm_program.key(),
        accounts: account_metas,
        data,
    };

    let account_infos = vec![
        accounts.pool,
        accounts.position,
        accounts.position_nft_account,
        accounts.owner,
        accounts.event_authority,
        accounts.damm_program,
    ];

    invoke_signed(&ix, &account_infos, signer_seeds)?;

    Ok(())
}
