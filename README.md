# PoW Solana Programs

A suite of Solana programs implementing Proof-of-Work mining with privacy-preserving features using Arcium MPC.

## Deployed Addresses

| | Address |
|---|---|
| **Program** | `PoWgG9zPrzF2vFUQRTyU4L1aNMZmbsemxJgwhycjtS4` |
| **Program Encrypted** | `EnchaSHvRoShUp6zrF2awSeQGVYjGFZfjpkdoi2nKPBk` |
| **Token Mint** | `HaShish4TSSxVg5gvEHLAttzifzapwPzmcH1MFtWjwC8` |

## Programs

### pow-protocol
Core PoW protocol for token minting based on hash difficulty.
- Submit proofs with valid SHA-256 hashes below target difficulty
- Dynamic difficulty adjustment based on block time
- Fee distribution (protocol fees, team fees, buyback)

### pow-privacy
Privacy layer using Arcium MPC for encrypted miner balances.
- Encrypted miner identity (SHA-256 hash of secret key)
- Private deposits/withdrawals with MPC verification
- Anonymous mining with fee deduction

### encrypted-ixs (Arcium MPC Circuits)

Privacy-preserving circuits executed on [Arcium](https://arcium.com)'s Multi-Party Computation (MPC) network. All data remains encrypted end-to-end — no single node can see plaintext values.

**How it works:**
- Miners are identified by `miner_id_hash = SHA-256(secret_key)`, keeping their on-chain identity anonymous
- Balances are stored and updated entirely within the MPC network (never exposed on-chain)
- Pubkeys are encoded as `[u64; 4]` (4 ciphertexts instead of 32) for efficiency
- Authentication is based on `miner_id_hash` — only someone who knows the `secret_key` can produce the correct hash, so possession of the hash proves ownership

**Relayer model:** A miner never submits blocks directly on-chain. Instead, an authorized relayer (set in `PrivacyConfig`) submits blocks on behalf of miners. The relayer cannot access miner funds — only the holder of the `secret_key` (and therefore the correct `miner_id_hash`) can deposit, withdraw, or trigger fee deductions.

**Circuits:**

| Circuit | Description | Inputs | Output |
|---------|-------------|--------|--------|
| `deposit_fee` | Deposit SOL to encrypted miner balance | `miner_id_hash`, `amount` | New balance + success |
| `mine_block` | Verify balance & deduct protocol fee on block submission (called by relayer) | `miner_id_hash`, `protocol_fee`, `encrypted_dest` | New balance + fee deducted + success |
| `withdraw_fee` | Withdraw SOL anonymously to any address | `miner_id_hash`, `amount`, `destination` | Destination + amount + new balance + success |
| `check_miner_balance` | Query encrypted balance | `miner_id_hash` | Balance + success |
| `store_claim` | Store encrypted destination for reward claim | `encrypted_dest` | Success |
| `verify_and_claim` | Verify secret & return decrypted destination | `claim_id`, `secret` | Destination + amount + success |
| `batch_claims` | Process up to 10 claims at once | `claim_ids[10]`, `secrets[10]` | Processed count + total amount + success |

**Mining flow:**
1. Miner generates a `secret_key` and derives `miner_id_hash = hash(secret_key)`
2. Miner deposits SOL via `deposit_fee` (balance tracked in MPC)
3. Relayer submits a block for the miner via `mine_block` — MPC matches the `miner_id_hash` and deducts the protocol fee
4. Miner can `withdraw_fee` remaining balance to any address — the withdrawal is fully anonymous: the buffer can be created from a throwaway wallet, and both the `miner_id_hash` and destination are encrypted. No on-chain link exists between the miner and the recipient
5. Rewards are claimed via `verify_and_claim` using the original secret

## Architecture

```
programs/
├── pow-protocol/     # Core PoW mining logic
└── pow-privacy/      # Arcium MPC privacy layer

encrypted-ixs/        # Arcium circuit definitions
```

## Prerequisites

- Rust 1.75+
- Anchor 0.32.1
- Solana CLI 1.18+
- Arcium CLI (for privacy features)

## Building

```bash
# Build all programs
anchor build

# Build specific program
anchor build -p pow-protocol

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
```

## License

MIT
