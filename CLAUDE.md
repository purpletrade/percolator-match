# Agent Context: percolator-match

This file gives any AI agent full context to maintain this repository.
Read this before making changes.

## What this repo is

A Solana on-chain program providing passive market-making and virtual AMM (vAMM)
functionality for the Percolator trading system. It quotes prices around an oracle
price with configurable spread and is invoked via CPI from Percolator's `TradeCpi`
instruction. It serves as a pluggable liquidity provider / matcher component.

## Critical facts

| Item | Value |
|------|-------|
| **Program ID** | Not yet assigned. Update `declare_id!()` before deploying. |
| **Relationship** | Called by percolator-prog via CPI (ABI-level, no crate dep) |
| **Solana version** | 2.x (`solana-program = "2.3.0"` in lockfile) |
| **Docker image** | `solanafoundation/solana-verifiable-build:2.3.0` |
| **Default branch** | `master` |
| **Lockfile format** | v4 |
| **Build target** | linux/amd64, SBF v1 |
| **Upstream** | `https://github.com/purpletrade/percolator-match` (branch: `master`) |
| **Last synced** | Commit `bddac64` (Feb 7, 2026) |

## Companion program

This program works alongside **percolator-prog** (`purpletrade/percolator-prog`):

```
percolator-prog (core engine)     percolator-match (market maker)
     |                                  |
     |  1. Deploy both independently    |
     |  2. Register matcher via InitLP  |
     |                                  |
     └──── TradeCpi ───── CPI call ────>|
           "get me a quote"              |
```

- They are **independent programs** with separate keypairs
- No compile-time dependency between them (ABI-level integration only)
- Deploy in any order; link at runtime via `InitLP` on percolator-prog

## Repository layout

```
percolator-match/
  src/
    lib.rs                   # Entrypoint, instruction dispatch, ABI types
    passive_lp_matcher.rs    # Passive mode: fixed spread around oracle
    vamm.rs                  # vAMM mode: spread + impact pricing, MatcherCtx
  Cargo.toml                 # Single dep: solana-program = "2.0"
  Cargo.lock                 # Pinned lockfile v4 (committed, never regenerate in CI)
  .cargo/config.toml         # Vendored source replacement
  vendor/                    # All dependencies vendored (offline builds)
  .github/workflows/
    verified-build.yml       # Manual dispatch: builds .so in Docker
    upstream-sync.yml        # Scheduled: checks for new commits
  CLAUDE.md                  # This file
```

## Build system

### Docker image

Uses `solanafoundation/solana-verifiable-build:2.3.0` (Solana 2.x).
If the image lacks `cargo` on PATH (like the 1.18.9 image), the workflow
installs Rust via rustup with `RUSTUP_HOME=/tmp/rustup CARGO_HOME=/tmp/cargo`.

### Lockfile

Committed as v4. Use `--locked` in CI. Do not regenerate in CI.

### Vendoring

All crates-io deps are vendored in `vendor/`. Simple setup (no git sources):
- `.cargo/config.toml` has `[source.crates-io] replace-with = "vendored-sources"`

After any dep change:
1. `cargo vendor vendor`
2. Commit `vendor/`, `.cargo/config.toml`, `Cargo.lock`

## Matcher modes

### Passive (kind=0)
Fixed spread around oracle price.
```
bid = floor(oracle * (10000 - spread_bps) / 10000)
ask = ceil(oracle * (10000 + spread_bps) / 10000)
```

### vAMM (kind=1)
Spread + price impact based on configurable liquidity curve.
Larger trades incur more slippage. Impact capped at `max_total_bps`.

## Instructions

| Tag | Name | Description |
|-----|------|-------------|
| 0 | Matcher Call | CPI from percolator-prog; executes match, returns 64-byte result |
| 2 | Init vAMM | One-time context initialization; stores LP PDA, mode, parameters |

## Context account layout (320 bytes)

```
Offset 0-63:   Matcher return data (64 bytes, ABI required)
Offset 64-319: MatcherCtx state (256 bytes)
  - magic (8), version (4), kind (1), pad (3)
  - lp_pda (32), fee params (16), liquidity params (32)
  - state (32), limits (16), reserved (112)
```

## Deployment

### Before deploying

1. Generate a program keypair (do NOT commit it)
2. Add `declare_id!("YOUR_PROGRAM_ID");` to `src/lib.rs`
3. Add `solana-security-txt` dep and `security_txt!` macro (optional, for green badge)
4. Build via CI, download artifact

### Deploy command

```bash
solana program deploy \
  --program-id /path/to/program-keypair.json \
  --upgrade-authority /path/to/upgrade-authority.json \
  --max-len 200000 \
  percolator_match.so
```

### Verify

```bash
echo "y" | solana-verify verify-from-repo --remote \
  --program-id <PROGRAM_ID> \
  https://github.com/purpletrade/percolator-match \
  --library-name percolator_match \
  --commit-hash $(git rev-parse HEAD)
```

## Rules for agents

1. **Never commit keypairs or secrets.** Check `.gitignore` excludes `*-keypair.json`.
2. **Never commit unless explicitly asked.**
3. **Never push unless explicitly asked.**
4. **Never deploy or run on-chain transactions.**
5. **Never regenerate Cargo.lock in CI.** Use committed lock with `--locked`.
6. **Keep `master` workflow files current.** GitHub reads workflow definitions
   from the default branch.
7. **After any dep change**: re-vendor, commit lockfile + vendor + config.
8. **Follow existing code style.** `#![no_std]`, integer-only math, no floats.
