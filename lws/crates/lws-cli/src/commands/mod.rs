pub mod config;
pub mod derive;
pub mod generate;
pub mod info;
pub mod send_transaction;
pub mod sign_message;
pub mod sign_transaction;
pub mod uninstall;
pub mod update;
pub mod wallet;

use crate::{vault, CliError};
use lws_core::KeyType;
use lws_signer::process_hardening::clear_env_var;
use lws_signer::{CryptoEnvelope, SecretBytes};
use std::io::{self, BufRead, IsTerminal, Write};

/// Read mnemonic from LWS_MNEMONIC env var or stdin. Used by the `derive` command.
pub fn read_mnemonic() -> Result<String, CliError> {
    if let Some(value) = clear_env_var("LWS_MNEMONIC") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter mnemonic: ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no mnemonic provided (set LWS_MNEMONIC or pipe via stdin)".into(),
        ));
    }

    Ok(trimmed)
}

/// Read a hex-encoded private key from LWS_PRIVATE_KEY env var or stdin.
pub fn read_private_key() -> Result<String, CliError> {
    if let Some(value) = clear_env_var("LWS_PRIVATE_KEY") {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Enter private key (hex): ");
        io::stderr().flush().ok();
    }

    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();

    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs(
            "no private key provided (set LWS_PRIVATE_KEY or pipe via stdin)".into(),
        ));
    }

    Ok(trimmed)
}

/// Resolved wallet secret — either a mnemonic phrase or a key pair (JSON).
pub enum WalletSecret {
    Mnemonic(String),
    /// JSON key pair: `{"secp256k1":"hex","ed25519":"hex"}`
    PrivateKeys(SecretBytes),
}

/// Read a passphrase from LWS_PASSPHRASE env var or prompt interactively.
pub fn read_passphrase() -> String {
    if let Some(value) = clear_env_var("LWS_PASSPHRASE") {
        return value;
    }
    let stdin = io::stdin();
    if stdin.is_terminal() {
        eprint!("Passphrase (empty for none): ");
        io::stderr().flush().ok();
        let mut line = String::new();
        stdin.lock().read_line(&mut line).unwrap_or(0);
        line.trim().to_string()
    } else {
        String::new()
    }
}

/// Look up a wallet by name or ID, decrypt it, and return the secret.
/// Handles both mnemonic and private key wallets.
pub fn resolve_wallet_secret(wallet_name: &str) -> Result<WalletSecret, CliError> {
    let wallet = vault::load_wallet_by_name_or_id(wallet_name)?;
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())?;

    // Try empty passphrase first, then prompt if it fails
    let secret = match lws_signer::decrypt(&envelope, "") {
        Ok(s) => s,
        Err(_) => {
            let passphrase = read_passphrase();
            lws_signer::decrypt(&envelope, &passphrase)?
        }
    };

    match wallet.key_type {
        KeyType::Mnemonic => {
            let phrase = String::from_utf8(secret.expose().to_vec())
                .map_err(|_| CliError::InvalidArgs("wallet contains invalid mnemonic".into()))?;
            Ok(WalletSecret::Mnemonic(phrase))
        }
        KeyType::PrivateKey => Ok(WalletSecret::PrivateKeys(secret)),
    }
}
