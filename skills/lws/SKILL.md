---
name: lws
description: Secure, local-first multi-chain wallet management — create wallets, derive addresses, sign messages and transactions across EVM, Solana, Bitcoin, Cosmos, Tron, and TON via CLI, Node.js, or Python.
version: 0.2.25
metadata:
  openclaw:
    requires:
      anyBins:
        - lws
        - node
        - python3
    emoji: "\U0001F511"
    homepage: https://openwallet.sh
    os:
      - darwin
      - linux
    install:
      - kind: node
        package: "@local-wallet-standard/node"
        bins: [lws]
        label: Install LWS Node.js SDK + CLI
---

# LWS — Local Wallet Standard

Secure, offline-first multi-chain wallet management. Private keys are encrypted at rest (AES-256-GCM, scrypt KDF) and decrypted only inside an isolated signing process — the caller never sees the raw key.

Available as **CLI**, **Node.js SDK** (`@local-wallet-standard/node`), and **Python SDK** (`local-wallet-standard`).

## When to use

Use this skill when the user asks to:

- Create, import, list, delete, or manage crypto wallets
- Derive blockchain addresses from a mnemonic
- Sign messages or transactions for EVM, Solana, Bitcoin, Cosmos, Tron, or TON
- Broadcast signed transactions to a chain
- Generate BIP-39 mnemonic phrases
- Work with `@local-wallet-standard/node` or `local-wallet-standard` in code

## Supported Chains

| Chain | Parameter | Curve | Address Format |
|-------|-----------|-------|----------------|
| EVM (Ethereum, Polygon, Base, etc.) | `evm` | secp256k1 | EIP-55 checksummed |
| Solana | `solana` | Ed25519 | base58 |
| Bitcoin | `bitcoin` | secp256k1 | BIP-84 bech32 |
| Cosmos | `cosmos` | secp256k1 | bech32 |
| Tron | `tron` | secp256k1 | base58check |
| TON | `ton` | Ed25519 | raw/bounceable |

## Installation

```bash
# CLI (one-liner)
curl -fsSL https://openwallet.sh/install.sh | bash

# Node.js SDK (global install also provides the lws CLI)
npm install @local-wallet-standard/node

# Python SDK
pip install local-wallet-standard
```

---

## CLI

### Wallet Management

```bash
# Create (--show-mnemonic to display the phrase for backup)
lws wallet create --name "my-wallet"
lws wallet create --name "my-wallet" --words 24 --show-mnemonic

# Import from mnemonic (via stdin or LWS_MNEMONIC env)
echo "goose puzzle decorate ..." | lws wallet import --name "imported" --mnemonic

# Import from private key (via stdin or LWS_PRIVATE_KEY env)
echo "4c0883a691..." | lws wallet import --name "from-evm" --private-key
echo "9d61b19d..." | lws wallet import --name "from-sol" --private-key --chain solana

# Import explicit keys for both curves
lws wallet import --name "both" \
  --secp256k1-key "4c0883a691..." \
  --ed25519-key "9d61b19d..."

# List / info / export / delete / rename
lws wallet list
lws wallet info
lws wallet export --wallet "my-wallet"
lws wallet delete --wallet "my-wallet" --confirm
lws wallet rename --wallet "my-wallet" --new-name "treasury"
```

### Signing

The `--wallet` flag can also be set via `LWS_WALLET` env var. Use `--json` for structured output, `--index N` to select an HD account index.

```bash
# Sign a message
lws sign message --wallet "my-wallet" --chain evm --message "hello world"
lws sign message --wallet "my-wallet" --chain solana --message "hello" --json

# Sign a message with EIP-712 typed data (EVM only)
lws sign message --wallet "my-wallet" --chain evm --message "" --typed-data '{"types":...}'

# Sign a raw transaction
lws sign tx --wallet "my-wallet" --chain evm --tx "02f8..."

# Sign and broadcast
lws sign send-tx --wallet "my-wallet" --chain evm --tx "02f8..." --rpc-url "https://..."
```

### Mnemonic Utilities

```bash
lws mnemonic generate --words 12
LWS_MNEMONIC="word1 word2 ..." lws mnemonic derive --chain evm
```

### System

```bash
lws update            # Update to latest version
lws update --force    # Force re-download
lws uninstall         # Remove CLI (keep wallet data)
lws uninstall --purge # Remove CLI + all wallet data
lws config show       # Show config and RPC endpoints
```

---

## Node.js SDK

`npm install @local-wallet-standard/node` — native NAPI bindings, Rust core runs in-process.

Quick start:

```javascript
import { createWallet, signMessage } from "@local-wallet-standard/node";

const wallet = createWallet("my-wallet");
const sig = signMessage("my-wallet", "evm", "hello world");
```

Full API reference, types, and examples: see `{baseDir}/references/node.md`

---

## Python SDK

`pip install local-wallet-standard` — native PyO3 bindings, Rust core runs in-process.

Quick start:

```python
from local_wallet_standard import create_wallet, sign_message

wallet = create_wallet("my-wallet")
sig = sign_message("my-wallet", "evm", "hello world")
```

Full API reference, return types, and examples: see `{baseDir}/references/python.md`

---

## Vault Layout

```
~/.lws/
  bin/
    lws                    # CLI binary
  wallets/
    <uuid>/
      wallet.json          # Encrypted keystore (AES-256-GCM, scrypt KDF)
      meta.json            # Name, chains, created_at
```

## Security Model

- Keys encrypted at rest with AES-256-GCM (scrypt N=2^15, r=8, p=1)
- Signing in isolated process — keys decrypted, used, wiped from memory
- Caller never sees raw private key during signing
- Optional passphrase adds second encryption layer
- Universal wallets: single mnemonic derives addresses for all 6 chains via BIP-44 HD paths
