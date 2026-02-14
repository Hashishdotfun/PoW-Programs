# PoW Solana Programs

A suite of Solana programs implementing Proof-of-Work mining with privacy-preserving features using [Arcium](https://arcium.com)'s Multi-Party Computation (MPC) network.

## Deployed Addresses (Devnet)

| | Address |
|---|---|
| **pow-protocol** | `Ai9XrxSUmDLNCXkoeoqnYuzPgN9F2PeF9WtLq9GyqER` |
| **pow-privacy** | `DJB2PeDYBLczs5ZxmUrqpoEAuejgdP516J3fNsEXVY5f` |
| **HASH Token Mint** | `ACnhuoJn41PQQKfhuHYgAQXR3jPSg1i4zr59Qt68QAUR` |

### On-chain PDAs

| PDA | Address |
|-----|---------|
| Privacy Config | `BL5xWCVe3bqbdcxAEGkRf7DybUY516s2thA5oCgD3CxJ` |
| Privacy Authority | `2efQ5uDQcrBGVaJu5MUuG6DgCHdeEUA9Fq1C8DprUpH1` |
| Shared Token Vault | `5ZM2J6VL4i3uBGKf8ySEa7N3pTnGqJRhd1ijoFLrDFny` |
| Shared Fee Vault | `AEdPa4qyDbShKd7L9Mv7w1FJ2WYWWAyGyS9Rp5CByVMQ` |
| mine_block CompDef | `6bqn5KSMUhBxpRowRH46idxkyNmxD9kP2pHJSzjZH5C1` |

## Technology Stack

- **Language**: Rust (edition 2021)
- **Framework**: Anchor 0.32.1
- **Blockchain**: Solana (SDK 2.2.0)
- **Privacy Layer**: Arcium MPC (arcium-anchor 0.8.0)
- **Token Standard**: SPL Token 2022

## Programs

### pow-protocol

Core PoW protocol with dual pool system for token minting based on SHA-256 hash difficulty.

**Dual Pool System:**
- **Pool Normal** (`pool_id=0`) — Open to all miners, no restrictions
- **Pool Seeker** (`pool_id=1`) — Requires TEE device attestation for Seekers (valid 60s, single-use)

Each pool has its own `PowConfig` PDA. Reward rates are halved per pool to maintain the same total emission schedule.

**Instructions:**
| Instruction | Description |
|-------------|-------------|
| `initialize(pool_id)` | Initialize a pool (0=normal, 1=seeker) with PDAs and config |
| `submit_proof(nonce)` | Submit a PoW proof — hash(challenge \|\| miner_pubkey \|\| nonce \|\| block_number) < target |
| `create_attestation` | Create/refresh TEE device attestation (seeker pool only, co-signed by backend) |
| `distribute_fees` | Permissionless — split fees: 5% team, 57% buyback, 38% LP |
| `execute_buyback` | Process tokens bought off-chain: 50% burn, 50% for LP |
| `withdraw_for_buyback` | Withdraw SOL from buyback vault to keeper for off-chain swap |
| `withdraw_for_lp` | Withdraw SOL from LP vault to keeper for liquidity provision |
| `update_config(params)` | Admin — update protocol parameters |
| `transfer_authority` | Admin — transfer authority (requires both old+new signatures) |
| `claim_team_fees(amount)` | Admin — withdraw accumulated team fees |
| `add_pending_reward(amount)` | Transfer hook callback — adds tax tokens to miner reward pool |
| `record_transfer_burn(amount)` | Transfer hook callback — records burned tokens for stats |

**Difficulty Adjustment (Proportional):**
| Block time ratio | Action |
|-----------------|--------|
| < 0.5 (< 30s) | ×2.0 difficulty |
| < 0.75 (30-45s) | ×1.5 difficulty |
| < 0.9 (45-54s) | ×1.1 difficulty |
| 0.9 – 1.1 (54-66s) | No change |
| ≤ 1.5 (66-90s) | ×0.9 difficulty |
| ≤ 2.0 (90-120s) | ×0.7 difficulty |
| > 2.0 (> 120s) | ×0.5 difficulty |

Uses a circular buffer of the last 10 block timestamps for moving average smoothing.

**Key State Accounts:**
- `PowConfig` — Global protocol configuration per pool (difficulty, rewards, fees, bumps, pool_id)
- `MinerStats` — Per-miner statistics (blocks mined, tokens earned)
- `MintAuthority` — Shared PDA that can mint tokens across both pools
- `DeviceAttestation` — Per-miner TEE attestation (seeker pool only)

### pow-privacy

Privacy layer using Arcium MPC for encrypted miner balances. Miners are identified by `miner_id_hash = SHA-256(secret_key)` — their on-chain identity stays anonymous.

**Architecture:**
- Mining is done through a **relayer model** — an authorized relayer submits blocks on behalf of miners via `submit_block_private`. The relayer cannot access miner funds
- Balances are stored and updated entirely within the MPC network (never exposed on-chain)
- Attestation is **not required** for privacy mining (only the normal pool is used, `pool_id=0`)
- Rewards are stored as `Claim` accounts with encrypted destination. Miners claim later using their secret

**Instructions:**

| Instruction | Description |
|-------------|-------------|
| `initialize` | Initialize privacy protocol with shared vaults (token vault, fee vault) |
| `initialize_vaults` | Create missing vault PDAs when privacy_config already exists |
| `init_*_comp_def` | Initialize Arcium computation definitions (5 circuits) |
| `submit_block_private(nonce, ...)` | Relayer submits block — verifies PoW, CPIs to pow-protocol, queues MPC, creates Claim |
| `init_claim_buffer` | Create buffer for encrypted claim data (tx 1 of multi-tx flow) |
| `append_claim_buffer` | Append data to claim buffer (tx 2+) |
| `init_claim_request_buffer` | Create claim request buffer (single tx) |
| `claim_reward(offset)` | Claim rewards using secret — queues Arcium MPC verification |
| `create_deposit_buffer` | Create deposit buffer with encrypted amount + state |
| `deposit_private(offset)` | Execute deposit — queues MPC balance update |
| `create_withdraw_buffer` | Create withdraw buffer with encrypted data |
| `withdraw_private(offset)` | Execute withdrawal — queues MPC verification |
| `deposit_fee(amount)` | Legacy simple SOL deposit to shared vault |
| `update_privacy_config(args)` | Admin — update privacy protocol config |

**CPI to pow-protocol:** `submit_block_private` calls `pow_protocol::submit_proof` via CPI, with `privacy_authority` PDA as the signer/miner. For the `Option<Account<DeviceAttestation>>` field in pow-protocol, the program passes its own program ID to signal `None` (Anchor convention for optional accounts).

**Key State Accounts:**
- `PrivacyConfig` — Protocol config (authority, mint, claim counters, bumps, is_active)
- `Claim` — Individual claim (id, amount, encrypted_destination, secret_hash, verification_pending)
- `ClaimBuffer` / `ClaimRequestBuffer` — Temporary buffers for encrypted claim data
- `DepositBuffer` / `WithdrawBuffer` / `MineBlockBuffer` — Balance operation buffers

**Arcium MPC Callbacks:**
- `mine_block_callback` — Marks claim as verified (MPC confirmed miner had sufficient balance)
- `deposit_fee_callback` — Marks deposit buffer as processed
- `withdraw_fee_callback` — Transfers SOL from shared fee vault to MPC-verified destination
- `verify_and_claim_callback` — Transfers tokens from shared vault to MPC-decrypted destination

### encrypted-ixs (Arcium MPC Circuits)

Privacy-preserving circuits executed on [Arcium](https://arcium.com)'s MPC network. All data remains encrypted end-to-end — no single node can see plaintext values.

**How it works:**
- Miners are identified by `miner_id_hash = SHA-256(secret_key)`, keeping their on-chain identity anonymous
- Balances tracked as `MinerState { balance, nonce, reserved }` in Arcium persistent state
- Pubkeys encoded as `[u64; 4]` (4 ciphertexts instead of 32) for efficiency
- Circuits are hosted as off-chain `.arcis` files (raw GitHub URLs) with hash verification

**Circuits:**

| Circuit | Description | Inputs | Output |
|---------|-------------|--------|--------|
| `deposit_fee` | Add SOL to encrypted miner balance | `amount`, `current_state` | `(MinerState, DepositFeeResult)` |
| `mine_block` | Verify balance & deduct protocol fee | `protocol_fee`, `current_state` | `(MinerState, MineBlockResult)` |
| `withdraw_fee` | Withdraw SOL anonymously to any address | `amount`, `destination`, `current_state` | `(MinerState, WithdrawFeeResult)` |
| `check_miner_balance` | Query encrypted balance | `current_state` | `CheckBalanceResult` |
| `store_claim` | Store encrypted destination for reward claim | `encrypted_dest` | `StoreClaimResult` |
| `verify_and_claim` | Verify secret & return decrypted destination | `claim_id`, `secret` | `VerifyAndClaimResult` |

**Privacy Mining Flow:**
1. Miner generates `secret_key` → derives `miner_id_hash = SHA-256(secret_key)`
2. Miner deposits SOL via `create_deposit_buffer` + `deposit_private` (balance tracked in MPC)
3. Relayer calls `submit_block_private` with encrypted data → CPI to `submit_proof` → MPC `mine_block` circuit deducts protocol fee
4. A `Claim` account is created with encrypted destination and reward amount
5. Miner calls `init_claim_request_buffer` + `claim_reward` with secret → MPC `verify_and_claim` decrypts destination → callback transfers tokens
6. Miner can `withdraw_fee` remaining SOL balance to any address (fully anonymous)

## Architecture

```
programs/
├── pow-protocol/         # Core PoW mining logic (dual pool)
│   └── src/
│       ├── lib.rs        # Program entry, tests
│       ├── state.rs      # PowConfig, MinerStats, MintAuthority, DeviceAttestation
│       ├── constants.rs  # Protocol parameters
│       ├── errors.rs     # PowError
│       └── instructions/
│           ├── initialize.rs
│           ├── submit_proof.rs
│           ├── create_attestation.rs
│           ├── distribute_fees.rs  # + execute_buyback, withdraw_for_*
│           ├── update_config.rs    # + transfer_authority, add_pending_reward
│           └── claim_team_fees.rs
└── pow-privacy/          # Arcium MPC privacy layer
    └── src/
        ├── lib.rs        # Program entry + Arcium callbacks + CompDef structs
        ├── state.rs      # PrivacyConfig, Claim, Buffers, Events
        ├── constants.rs  # PDA seeds, limits
        ├── errors.rs     # ErrorCode
        └── instructions/
            ├── initialize.rs
            ├── initialize_vaults.rs
            ├── submit_block_private.rs
            ├── create_claim_buffer.rs
            ├── create_claim_request_buffer.rs
            ├── claim_reward.rs
            ├── create_deposit_buffer.rs
            ├── deposit_private.rs
            ├── create_withdraw_buffer.rs
            ├── withdraw_private.rs
            ├── deposit_fee.rs
            └── admin.rs

encrypted-ixs/           # Arcium circuit definitions (.arcis)
├── Cargo.toml
└── src/lib.rs            # 6 circuits: deposit_fee, mine_block, withdraw_fee, etc.

## Important Constants

```
Token
  MAX_SUPPLY         = 1,000,000 tokens (9 decimals)
  PREMINT_TOKENS     = 1,000 tokens (initial LP)

Timing
  TARGET_BLOCK_TIME  = 60 seconds
  BOOST_DURATION     = 1 year

Rewards (per pool, halved for dual-pool)
  R0_BOOST           = 44,350,000 (0.04435 tokens — first year)
  R0_NORMAL          = 28,700,000 (0.0287 tokens — after first year)
  DECAY_FACTOR       = 0.999999943 per block (~2.95% yearly decay)

Fees
  FEE_INITIAL_SOL    = 1,000,000 (0.001 SOL)
  FEE_MULTIPLIER     = 1.5x every 2 years
  FEE_SOL_CAP        = 500,000,000 (0.5 SOL)
  TEAM_FEE_PCT       = 5%
  PROTO_FEE_PCT      = 95% (60% buyback, 40% LP)

Transfer Tax (SPL 2022)
  TAX_RATE           = 0.01% (1 basis point)
  50% burned, 50% to miner reward pool

Difficulty
  INITIAL_DIFFICULTY = 10,000
  MIN_DIFFICULTY     = 1,000
  MAX_DIFFICULTY     = u128::MAX / 1000

Privacy
  MAX_PENDING_CLAIMS = 1,000,000
  CLAIM_EXPIRY       = 1 year
```

## Prerequisites

- Rust 1.75+
- Anchor 0.32.1
- Solana CLI 2.2+
- Arcium CLI (for circuit builds)

## Building

```bash
# Build all programs
anchor build

# Build specific program
anchor build -p pow-protocol
anchor build -p pow-privacy

# Build Arcium circuits
cd encrypted-ixs && arcium build
```

## Deployment

```bash
# Deploy to devnet
anchor deploy --provider.cluster devnet

# Deploy specific program
anchor deploy -p pow-privacy --provider.cluster devnet
```

## Testing

```bash
# Run all tests
anchor test

# Run specific test
anchor test --skip-deploy -- --test pow_tests

# Run unit tests only
cargo test
```

## Security

- **Proof includes miner pubkey** — prevents proof theft
- **Difficulty uses moving average** (10 block circular buffer) — prevents manipulation
- **Challenge uses block_number** — ensures uniqueness
- **MPC callbacks verify BLS signatures** — all Arcium outputs are authenticated
- **Authority transfer requires both signatures** — prevents accidental lockout
- **Supply cap enforced across both pools** — `combined_supply < MAX_SUPPLY`
- **Optional attestation** via `Option<Account>` — seeker pool requires TEE, normal pool skips it

## License

MIT
