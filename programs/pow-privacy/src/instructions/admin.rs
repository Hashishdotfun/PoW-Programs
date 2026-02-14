use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::ErrorCode;
use crate::state::*;

/// Update protocol configuration (admin only)
pub fn handler(ctx: Context<UpdatePrivacyConfig>, args: PrivacyConfigArgs) -> Result<()> {
    let config = &mut ctx.accounts.privacy_config;

    if let Some(is_active) = args.is_active {
        config.is_active = is_active;
    }

    emit!(ConfigUpdated {
        is_active: args.is_active,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct UpdatePrivacyConfig<'info> {
    /// Admin authority
    #[account(
        constraint = authority.key() == privacy_config.authority @ ErrorCode::Unauthorized
    )]
    pub authority: Signer<'info>,

    /// Privacy protocol configuration
    #[account(
        mut,
        seeds = [PRIVACY_CONFIG_SEED],
        bump = privacy_config.bump,
    )]
    pub privacy_config: Account<'info, PrivacyConfig>,
}
