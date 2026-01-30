#![allow(ambiguous_glob_reexports)]

pub mod initialize;
pub mod submit_block_private;
pub mod claim_reward;
pub mod deposit_fee;
pub mod admin;
pub mod create_claim_buffer;
pub mod create_claim_request_buffer;
pub mod create_deposit_buffer;
pub mod deposit_private;
pub mod create_withdraw_buffer;
pub mod withdraw_private;

// Re-export all public items - Anchor's #[program] macro needs these exports
// The `handler` functions have the same name across modules but are always
// called via their full path (e.g., instructions::initialize::handler)
pub use initialize::*;
pub use submit_block_private::*;
pub use claim_reward::*;
pub use deposit_fee::*;
pub use admin::*;
pub use create_claim_buffer::*;
pub use create_claim_request_buffer::*;
pub use create_deposit_buffer::*;
pub use deposit_private::*;
pub use create_withdraw_buffer::*;
pub use withdraw_private::*;
