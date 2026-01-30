use anchor_lang::prelude::*;
use anchor_lang::system_program::{transfer, Transfer};

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;

/// Deposit SOL into the shared fee vault
/// This SOL is used to pay protocol fees when submitting blocks
///
/// Anyone can deposit - this allows:
/// - Miners to fund the vault anonymously
/// - Protocol to pre-fund for operations
/// - Third parties to sponsor mining
pub fn handler(ctx: Context<DepositFee>, amount: u64) -> Result<()> {
    let config = &ctx.accounts.privacy_config;

    // Verify protocol is active
    require!(config.is_active, ErrorCode::ProtocolInactive);

    // Transfer SOL from depositor to fee vault
    transfer(
        CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            Transfer {
                from: ctx.accounts.depositor.to_account_info(),
                to: ctx.accounts.shared_fee_vault.to_account_info(),
            },
        ),
        amount,
    )?;

    let new_balance = ctx.accounts.shared_fee_vault.lamports();

    emit!(FeeDeposited {
        amount,
        new_balance,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct DepositFee<'info> {
    /// Anyone can deposit
    #[account(mut)]
    pub depositor: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,

    /// Shared fee vault
    /// CHECK: PDA verified by seeds
    #[account(
        mut,
        seeds = [SHARED_FEE_VAULT_SEED, privacy_config.key().as_ref()],
        bump = privacy_config.fee_vault_bump,
    )]
    pub shared_fee_vault: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}
