// =============================================================================
// MODULE DES INSTRUCTIONS
// =============================================================================

pub mod initialize;
pub mod submit_proof;
pub mod create_attestation;
pub mod close_attestation;
pub mod update_config;
pub mod claim_team_fees;
pub mod distribute_fees;
pub mod collect_transfer_fees;
pub mod initialize_fee_vault;

// Re-export all public items - Anchor's #[program] macro needs these exports
// The `handler` functions have the same name across modules but are always
// called via their full path (e.g., instructions::initialize::handler)
#[allow(ambiguous_glob_reexports)]
pub use initialize::*;
pub use submit_proof::*;
pub use create_attestation::*;
pub use close_attestation::*;
pub use update_config::*;
pub use claim_team_fees::*;
pub use distribute_fees::*;
pub use collect_transfer_fees::*;
pub use initialize_fee_vault::*;
