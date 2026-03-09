use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;
use crate::state::DeviceAttestation;

pub fn handler(ctx: Context<CloseAttestation>) -> Result<()> {
    msg!(
        "Closing attestation for miner {} and returning rent to {}",
        ctx.accounts.miner.key(),
        ctx.accounts.rent_recipient.key()
    );

    Ok(())
}

#[derive(Accounts)]
pub struct CloseAttestation<'info> {
    #[account(mut)]
    pub miner: Signer<'info>,

    #[account(
        mut,
        seeds = [DEVICE_ATTEST_SEED, miner.key().as_ref()],
        bump = attestation.bump,
        has_one = miner @ PowError::Unauthorized,
        has_one = rent_recipient @ PowError::InvalidAttestationRentRecipient,
        close = rent_recipient,
    )]
    pub attestation: Account<'info, DeviceAttestation>,

    /// CHECK: must match `attestation.rent_recipient`
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,
}