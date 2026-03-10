# CLI Reference

> Command-line interface for managing wallets, signing, and key operations.

## Install

```bash
curl -fsSL https://openwallet.sh/install.sh | bash
```

Or build from source:

```bash
git clone https://github.com/dawnlabsai/lws.git
cd lws/lws
cargo build --workspace --release
```

## Wallet Commands

### `lws wallet create`

Create a new wallet. Generates a BIP-39 mnemonic and derives addresses for all supported chains.

```bash
lws wallet create --name "my-wallet"
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--passphrase <PASS>` | Encryption passphrase (prompted if omitted) |
| `--words <12\|24>` | Mnemonic word count (default: 12) |

Output:

```
Created wallet 3198bc9c-...
  eip155:1                              0xab16...   m/44'/60'/0'/0/0
  solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp  7Kz9...    m/44'/501'/0'/0'
  bip122:000000000019d6689c085ae165831e93   bc1q...    m/84'/0'/0'/0/0
  cosmos:cosmoshub-4                     cosmos1... m/44'/118'/0'/0/0
  tron:mainnet                           TKLm...    m/44'/195'/0'/0/0
```

### `lws wallet import`

Import an existing wallet from a mnemonic or private key.

```bash
# Import from mnemonic (reads from LWS_MNEMONIC env or stdin)
echo "goose puzzle decorate ..." | lws wallet import --name "imported" --mnemonic

# Import from private key (reads from LWS_PRIVATE_KEY env or stdin)
echo "4c0883a691..." | lws wallet import --name "from-evm" --private-key

# Import an Ed25519 key (e.g. from Solana)
echo "9d61b19d..." | lws wallet import --name "from-sol" --private-key --chain solana
```

| Flag | Description |
|------|-------------|
| `--name <NAME>` | Wallet name (required) |
| `--mnemonic` | Import a mnemonic phrase |
| `--private-key` | Import a raw private key |
| `--chain <CHAIN>` | Source chain for private key import (determines curve, default: evm) |
| `--index <N>` | Account index for HD derivation (mnemonic only, default: 0) |

Private key imports generate all 6 chain accounts: the provided key is used for its curve's chains, and a random key is generated for the other curve.

### `lws wallet export`

Export a wallet's secret to stdout. Requires an interactive terminal.

```bash
lws wallet export --wallet "my-wallet"
```

- Mnemonic wallets output the phrase.
- Private key wallets output JSON: `{"secp256k1":"hex...","ed25519":"hex..."}`.

If the wallet is passphrase-protected, you will be prompted.

### `lws wallet list`

List all wallets in the vault.

```bash
lws wallet list
```

### `lws wallet info`

Show vault path and supported chains.

```bash
lws wallet info
```

## Signing Commands

### `lws sign message`

Sign a message with chain-specific formatting (e.g., EIP-191 for EVM, `\x19TRON Signed Message` for Tron).

```bash
lws sign message --wallet "my-wallet" --chain evm --message "hello world"
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain family: `evm`, `solana`, `bitcoin`, `cosmos`, `tron` |
| `--message <MSG>` | Message to sign |
| `--passphrase <PASS>` | Decryption passphrase |
| `--encoding <ENC>` | Message encoding: `utf8` (default) or `hex` |

### `lws sign tx`

Sign a raw transaction (hex-encoded bytes).

```bash
lws sign tx --wallet "my-wallet" --chain evm --tx-hex "02f8..."
```

| Flag | Description |
|------|-------------|
| `--wallet <NAME>` | Wallet name or ID |
| `--chain <CHAIN>` | Chain family |
| `--tx-hex <HEX>` | Hex-encoded transaction bytes |
| `--passphrase <PASS>` | Decryption passphrase |

## Mnemonic Commands

### `lws mnemonic generate`

Generate a new BIP-39 mnemonic phrase.

```bash
lws mnemonic generate --words 24
```

### `lws mnemonic derive`

Derive an address from a mnemonic for a given chain. Reads the mnemonic from the `LWS_MNEMONIC` environment variable or stdin.

```bash
echo "word1 word2 ..." | lws mnemonic derive --chain evm
```

## System Commands

### `lws update`

Update the `lws` binary to the latest release. Also updates Node.js and Python bindings if they are installed.

```bash
lws update
lws update --force   # re-download even if already on latest
```

### `lws uninstall`

Remove `lws` from the system. Also uninstalls Node.js and Python bindings if present.

```bash
lws uninstall          # keep wallet data
lws uninstall --purge  # also remove ~/.lws (all wallet data)
```

## File Layout

```
~/.lws/
  bin/
    lws                  # CLI binary
  wallets/
    <uuid>/
      wallet.json        # Encrypted keystore (Keystore v3)
      meta.json          # Name, chain, creation time
```
