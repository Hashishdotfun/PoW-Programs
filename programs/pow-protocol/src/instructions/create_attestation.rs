// =============================================================================
// INSTRUCTION: CREATE ATTESTATION
// =============================================================================
// Crée ou met à jour une attestation device après vérification TEE par le backend.
// L'authority (backend) doit signer. Le miner paie le rent.

use anchor_lang::prelude::*;

use crate::constants::*;
use crate::errors::PowError;
use crate::state::{DeviceAttestation, PowConfig};

/// Crée ou rafraîchit une attestation device.
///
/// Le backend vérifie le hardware (TEE) et co-signe cette transaction.
/// L'attestation est valide pendant 60 secondes on-chain.
pub fn handler(ctx: Context<CreateAttestation>) -> Result<()> {
    let clock = Clock::get()?;

    // Vérifier que l'authority est bien celle configurée dans pow_config
    require!(
        ctx.accounts.authority.key() == ctx.accounts.pow_config.attestation_authority,
        PowError::InvalidAttestationAuthority
    );

    // Vérifier que attestation_authority n'est pas default (disabled)
    require!(
        ctx.accounts.pow_config.attestation_authority != Pubkey::default(),
        PowError::InvalidAttestationAuthority
    );

    let attestation = &mut ctx.accounts.attestation;
    attestation.miner = ctx.accounts.miner.key();
    attestation.authority = ctx.accounts.authority.key();
    attestation.timestamp = clock.unix_timestamp;
    attestation.bump = ctx.bumps.attestation;
    attestation.is_used = false; // Fresh attestation, ready to be consumed by submit_proof

    msg!(
        "Device attestation created for miner {} at ts {}",
        ctx.accounts.miner.key(),
        clock.unix_timestamp
    );

    Ok(())
}

// =============================================================================
// CONTEXTE DE L'INSTRUCTION
// =============================================================================

#[derive(Accounts)]
pub struct CreateAttestation<'info> {
    /// Le mineur (paye le rent si première création)
    #[account(mut)]
    pub miner: Signer<'info>,

    /// L'authority backend qui a vérifié le device TEE
    pub authority: Signer<'info>,

    /// PowConfig de la pool seeker (contient l'attestation_authority)
    #[account(
        seeds = [POW_CONFIG_SEED, &[POOL_SEEKER]],
        bump = pow_config.bump,
    )]
    pub pow_config: Account<'info, PowConfig>,

    /// L'attestation PDA (créée ou mise à jour)
    #[account(
        init_if_needed,
        payer = miner,
        space = DeviceAttestation::LEN,
        seeds = [DEVICE_ATTEST_SEED, miner.key().as_ref()],
        bump,
    )]
    pub attestation: Account<'info, DeviceAttestation>,

    pub system_program: Program<'info, System>,
}
