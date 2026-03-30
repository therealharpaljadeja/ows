# EIP-712 Typed Data Signing via API Key

**Date:** 2026-03-30
**Status:** Approved

## Summary

Enable EIP-712 typed data signing through the API key (agent) path. Currently hard-blocked at three enforcement points. The underlying cryptography is complete — `EvmSigner::sign_typed_data` works, `decrypt_key_from_api_key` produces a usable private key — so the gap is purely in the dispatch and policy layers.

The implementation adds structured EIP-712 context to `PolicyContext` and a new declarative policy rule (`AllowedTypedDataContracts`) so that policies can inspect and restrict typed data signing without requiring an executable policy.

## Design Decisions

### 1. Structured typed data in PolicyContext (not raw-only)

EIP-712 signatures carry rich, structured semantics (domain, types, primary type, named fields). Unlike raw messages, a typed data signature can authorize token approvals, NFT listings, governance votes, and other high-consequence actions. Passing only `raw_hex` would force every policy author to parse EIP-712 JSON themselves. Instead, we expose a structured `TypedDataContext` so both declarative rules and executable policies can inspect typed data natively.

### 2. `AllowedTypedDataContracts` declarative rule

A single new declarative rule that whitelists `domain.verifyingContract` addresses. This covers the most dangerous scenario — signing typed data for an arbitrary contract — with zero user code. More granular restrictions (primary type filtering, field-level constraints) are handled by executable policies, which receive the full `TypedDataContext`.

### 3. Mirror `sign_message_with_api_key` (no shared helper refactor)

The new `sign_typed_data_with_api_key` function follows the same pattern as `sign_message_with_api_key` rather than extracting a shared preamble. This keeps the change isolated to new code without touching the two existing working signing paths. The ~30 lines of shared validation logic (token lookup, expiry, scope, policy load) are acceptable duplication — a cleanup refactor can happen separately if desired.

## Type Changes

### `TypedDataContext` (new struct in `ows-core/src/policy.rs`)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataContext {
    pub verifying_contract: Option<String>,  // domain.verifyingContract
    pub domain_chain_id: Option<u64>,        // domain.chainId
    pub primary_type: String,                // e.g. "Permit", "Order"
    pub domain_name: Option<String>,         // domain.name
    pub domain_version: Option<String>,      // domain.version
    pub raw_json: String,                    // full typed data JSON for executable policies
}
```

All domain fields are optional per the EIP-712 spec (a domain can omit any field). `raw_json` gives executable policies the full payload.

### `PolicyContext` — new optional field

```rust
pub struct PolicyContext {
    // ... existing fields unchanged ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typed_data: Option<TypedDataContext>,
}
```

`skip_serializing_if` ensures the field is omitted (not `null`) for non-typed-data signing calls, so existing executable policies see no change in their stdin payload.

### `PolicyRule` — new variant

```rust
pub enum PolicyRule {
    AllowedChains { chain_ids: Vec<String> },
    ExpiresAt { timestamp: String },
    AllowedTypedDataContracts { contracts: Vec<String> },  // NEW
}
```

Serialized as `{ "type": "allowed_typed_data_contracts", "contracts": ["0x..."] }`.

## Rule Evaluation: `AllowedTypedDataContracts`

In `policy_engine.rs`, a new function `eval_allowed_typed_data_contracts`:

| `ctx.typed_data` | `verifying_contract` | Result |
|---|---|---|
| `None` (sign_message/sign_transaction) | N/A | **Allow** — rule only constrains typed data |
| `Some(...)` | `None` (domain omits it) | **Deny** — can't verify contract if signature doesn't declare one |
| `Some(...)` | `Some(addr)` in whitelist | **Allow** |
| `Some(...)` | `Some(addr)` not in whitelist | **Deny** |

Address comparison is case-insensitive (lowercased on both sides) to handle mixed checksummed/non-checksummed inputs.

## Core Signing Flow

### New function: `sign_typed_data_with_api_key` in `key_ops.rs`

```rust
pub fn sign_typed_data_with_api_key(
    token: &str,
    wallet_name_or_id: &str,
    chain: &Chain,
    typed_data_json: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<SignResult, OwsLibError>
```

Steps:
1. **EVM-only gate** — reject non-EVM chains before any token lookup.
2. Token hash, key file lookup, expiry check, wallet scope check (same as `sign_message_with_api_key`).
3. **Parse typed data early** — `eip712::parse_typed_data(typed_data_json)` before policy evaluation. Validates JSON structure and extracts domain fields. Malformed JSON fails before the policy engine runs.
4. **Build `PolicyContext`** — `transaction.raw_hex = hex::encode(typed_data_json.as_bytes())`. `typed_data = Some(TypedDataContext { ... })` populated from parsed EIP-712 structure.
5. **Policy evaluation** — declarative rules (including `AllowedTypedDataContracts`) then executables.
6. **Decrypt key** — `decrypt_key_from_api_key` (existing, unchanged).
7. **Sign** — `EvmSigner::sign_typed_data(key.expose(), typed_data_json)`.
8. Return `SignResult`.

### Security properties preserved

- **Policy before key material** — private key never decrypted if policy denies.
- **Fail-closed** — malformed JSON, failed executable, timeout all deny.
- **Scope check before policy** — wallet must be in `key_file.wallet_ids` before policies run.
- **EVM-only validated first** — cheapest check runs earliest.

### Dispatcher change in `ops.rs`

Replace the hard-block at lines 506-511 with delegation to `key_ops::sign_typed_data_with_api_key`.

### CLI change in `sign_message.rs`

Remove the guard at lines 21-25. When token + typed_data, delegate to `ows_lib::sign_typed_data(...)` which now routes to the API key path.

## Binding and Compatibility

### No changes needed to bindings

Both Node.js and Python `sign_typed_data` exports already delegate to `ows_lib::sign_typed_data(...)`. The credential (passphrase or token) passes through — the dispatcher in `ops.rs` handles routing.

### Backwards compatibility

- **Existing API keys** — unchanged. Policies without `AllowedTypedDataContracts` work as before.
- **Existing policies** — unchanged. The new rule variant is additive to `PolicyRule`.
- **Existing executable policies** — `typed_data` is omitted entirely from stdin JSON for non-typed-data calls (not `null`). No breaking change.
- **`PolicyContext` serialization** — `typed_data` uses `skip_serializing_if = "Option::is_none"`, omitted entirely for non-typed-data calls.

## Documentation Updates

- `docs/sdk-node.md` line 267 — remove "API-token typed-data signing is not yet supported."
- `docs/sdk-python.md` line 225 — remove the same note.
- `docs/03-policy-engine.md` — add `AllowedTypedDataContracts` rule docs, `TypedDataContext` schema, and example policy JSON.

## Testing

### Unit tests (policy_engine.rs)

- `allowed_typed_data_contracts` + matching contract -> allow
- `allowed_typed_data_contracts` + non-matching contract -> deny
- `allowed_typed_data_contracts` + mixed-case addresses -> allow
- `allowed_typed_data_contracts` + `typed_data: None` (sign_message) -> allow (passthrough)
- `allowed_typed_data_contracts` + `typed_data: Some` with no `verifying_contract` -> deny
- Combined rules: `AllowedChains` + `AllowedTypedDataContracts` + `ExpiresAt` AND semantics

### Integration tests (key_ops.rs)

- Happy path: valid key + valid typed data + allowing policy -> valid signature
- EVM-only: non-EVM chain -> error before token lookup
- Expired key -> `ApiKeyExpired`
- Out-of-scope wallet -> error
- Malformed typed data JSON -> error before policy evaluation
- `AllowedTypedDataContracts` match -> signature
- `AllowedTypedDataContracts` no match -> `PolicyDenied`
- Executable policy receiving `TypedDataContext` on stdin -> verify structured fields
- Signature recovery: verify recovered address matches wallet's derived address

### Binding tests

- Node.js: `signTypedData` with API key -> valid signature; with denying policy -> policy denied error
- Python: same two cases

### Explicitly skipped

- No changes to `sign_message` / `sign_transaction` tests (untouched paths)
- No CLI e2e tests (4-line guard removal, library path is integration-tested)

## Files Changed

| File | Change |
|---|---|
| `ows/crates/ows-core/src/policy.rs` | Add `TypedDataContext` struct, `AllowedTypedDataContracts` variant to `PolicyRule`, `typed_data: Option<TypedDataContext>` to `PolicyContext` |
| `ows/crates/ows-lib/src/key_ops.rs` | Add `sign_typed_data_with_api_key` function |
| `ows/crates/ows-lib/src/ops.rs` | Replace hard-block with delegation to `key_ops::sign_typed_data_with_api_key` |
| `ows/crates/ows-lib/src/policy_engine.rs` | Add `eval_allowed_typed_data_contracts`, add match arm in `evaluate_rule` |
| `ows/crates/ows-cli/src/commands/sign_message.rs` | Remove 4-line API key + typed data guard |
| `docs/sdk-node.md` | Remove "not yet supported" note |
| `docs/sdk-python.md` | Remove "not yet supported" note |
| `docs/03-policy-engine.md` | Add new rule and context documentation |
