# EIP-712 Typed Data Signing via API Key — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable EIP-712 typed data signing through the API key (agent) path, with structured policy context and a new `AllowedTypedDataContracts` declarative rule.

**Architecture:** Add `TypedDataContext` to `PolicyContext`, add `AllowedTypedDataContracts` to `PolicyRule`, add `sign_typed_data_with_api_key` in `key_ops.rs` mirroring the existing `sign_message_with_api_key` pattern, remove hard-blocks in `ops.rs` and CLI.

**Tech Stack:** Rust (ows-core, ows-lib, ows-signer, ows-cli), NAPI (Node.js bindings), PyO3 (Python bindings)

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `ows/crates/ows-core/src/policy.rs` | Modify | Add `TypedDataContext` struct, `AllowedTypedDataContracts` variant, `typed_data` field on `PolicyContext` |
| `ows/crates/ows-lib/src/policy_engine.rs` | Modify | Add `eval_allowed_typed_data_contracts`, new match arm in `evaluate_rule` |
| `ows/crates/ows-lib/src/key_ops.rs` | Modify | Add `sign_typed_data_with_api_key` function |
| `ows/crates/ows-lib/src/ops.rs` | Modify | Replace hard-block with delegation to `key_ops::sign_typed_data_with_api_key` |
| `ows/crates/ows-cli/src/commands/sign_message.rs` | Modify | Remove API key + typed data guard, add delegation path |
| `docs/sdk-node.md` | Modify | Remove "not yet supported" note |
| `docs/sdk-python.md` | Modify | Remove "not yet supported" note |
| `docs/03-policy-engine.md` | Modify | Add `AllowedTypedDataContracts` rule and `TypedDataContext` docs |

---

### Task 1: Add `TypedDataContext` and update `PolicyContext`

**Files:**
- Modify: `ows/crates/ows-core/src/policy.rs`

- [ ] **Step 1: Add `TypedDataContext` struct**

In `ows/crates/ows-core/src/policy.rs`, add the new struct after the `SpendingContext` struct (after line 72):

```rust
/// EIP-712 typed data context for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedDataContext {
    /// The `domain.verifyingContract` address (if present in the EIP-712 domain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_contract: Option<String>,
    /// The `domain.chainId` (if present in the EIP-712 domain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_chain_id: Option<u64>,
    /// The EIP-712 `primaryType` (e.g. "Permit", "Order").
    pub primary_type: String,
    /// The `domain.name` (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    /// The `domain.version` (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_version: Option<String>,
    /// The full typed data JSON for executable policies to inspect.
    pub raw_json: String,
}
```

- [ ] **Step 2: Add `typed_data` field to `PolicyContext`**

In the `PolicyContext` struct (line 40), add the new field after `timestamp`:

```rust
pub struct PolicyContext {
    pub chain_id: String,
    pub wallet_id: String,
    pub api_key_id: String,
    pub transaction: TransactionContext,
    pub spending: SpendingContext,
    pub timestamp: String,
    /// EIP-712 typed data context (only present for `sign_typed_data` calls).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typed_data: Option<TypedDataContext>,
}
```

- [ ] **Step 3: Fix all existing `PolicyContext` construction sites**

Adding a new required field to `PolicyContext` will cause compile errors everywhere it's constructed. Add `typed_data: None` to every existing construction site:

In `ows/crates/ows-lib/src/key_ops.rs`, function `sign_with_api_key` (line 113):
```rust
    let context = ows_core::PolicyContext {
        chain_id: chain.chain_id.to_string(),
        wallet_id: wallet.id.clone(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: tx_hex,
            data: None,
        },
        spending: noop_spending_context(&date),
        timestamp: now.to_rfc3339(),
        typed_data: None,
    };
```

In `ows/crates/ows-lib/src/key_ops.rs`, function `sign_message_with_api_key` (line 176):
```rust
    let context = ows_core::PolicyContext {
        chain_id: chain.chain_id.to_string(),
        wallet_id: wallet.id.clone(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: hex::encode(msg_bytes),
            data: None,
        },
        spending: noop_spending_context(&date),
        timestamp: now.to_rfc3339(),
        typed_data: None,
    };
```

In `ows/crates/ows-lib/src/key_ops.rs`, function `enforce_policy_and_decrypt_key` (line 236):
```rust
    let context = ows_core::PolicyContext {
        chain_id: chain.chain_id.to_string(),
        wallet_id: wallet.id.clone(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: tx_hex,
            data: None,
        },
        spending: noop_spending_context(&date),
        timestamp: now.to_rfc3339(),
        typed_data: None,
    };
```

In `ows/crates/ows-lib/src/policy_engine.rs`, test helper `base_context` (line 191):
```rust
    fn base_context() -> PolicyContext {
        PolicyContext {
            chain_id: "eip155:8453".to_string(),
            wallet_id: "wallet-1".to_string(),
            api_key_id: "key-1".to_string(),
            transaction: TransactionContext {
                to: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C".to_string()),
                value: Some("100000000000000000".to_string()),
                raw_hex: "0x02f8...".to_string(),
                data: None,
            },
            spending: SpendingContext {
                daily_total: "50000000000000000".to_string(),
                date: "2026-03-22".to_string(),
            },
            timestamp: "2026-03-22T10:35:22Z".to_string(),
            typed_data: None,
        }
    }
```

In `ows/crates/ows-core/src/policy.rs`, test `test_policy_context_serde` (line 179):
```rust
        let ctx = PolicyContext {
            chain_id: "eip155:8453".into(),
            wallet_id: "3198bc9c-6672-5ab3-d995-4942343ae5b6".into(),
            api_key_id: "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c".into(),
            transaction: TransactionContext {
                to: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C".into()),
                value: Some("100000000000000000".into()),
                raw_hex: "0x02f8...".into(),
                data: None,
            },
            spending: SpendingContext {
                daily_total: "50000000000000000".into(),
                date: "2026-03-22".into(),
            },
            timestamp: "2026-03-22T10:35:22Z".into(),
            typed_data: None,
        };
```

- [ ] **Step 4: Add serde tests for the new types**

In `ows/crates/ows-core/src/policy.rs`, add these tests to the existing `mod tests` block:

```rust
    #[test]
    fn test_typed_data_context_serde() {
        let ctx = TypedDataContext {
            verifying_contract: Some("0x000000000022D473030F116dDEE9F6B43aC78BA3".into()),
            domain_chain_id: Some(8453),
            primary_type: "PermitSingle".into(),
            domain_name: Some("Permit2".into()),
            domain_version: Some("1".into()),
            raw_json: r#"{"types":{},"primaryType":"PermitSingle","domain":{},"message":{}}"#.into(),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: TypedDataContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.primary_type, "PermitSingle");
        assert_eq!(
            deserialized.verifying_contract.as_deref(),
            Some("0x000000000022D473030F116dDEE9F6B43aC78BA3")
        );
        assert_eq!(deserialized.domain_chain_id, Some(8453));
    }

    #[test]
    fn test_typed_data_context_optional_fields_omitted() {
        let ctx = TypedDataContext {
            verifying_contract: None,
            domain_chain_id: None,
            primary_type: "Mail".into(),
            domain_name: None,
            domain_version: None,
            raw_json: "{}".into(),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("verifying_contract"));
        assert!(!json.contains("domain_chain_id"));
        assert!(!json.contains("domain_name"));
        assert!(!json.contains("domain_version"));
    }

    #[test]
    fn test_policy_context_typed_data_none_omitted() {
        let ctx = PolicyContext {
            chain_id: "eip155:8453".into(),
            wallet_id: "w".into(),
            api_key_id: "k".into(),
            transaction: TransactionContext {
                to: None,
                value: None,
                raw_hex: "0x00".into(),
                data: None,
            },
            spending: SpendingContext {
                daily_total: "0".into(),
                date: "2026-03-30".into(),
            },
            timestamp: "2026-03-30T12:00:00Z".into(),
            typed_data: None,
        };

        let json = serde_json::to_string(&ctx).unwrap();
        assert!(!json.contains("typed_data"));
    }
```

- [ ] **Step 5: Build and run tests**

Run: `cd /Users/gustavo/apps/ows-core && cargo test -p ows-core -p ows-lib`

Expected: All existing tests pass, new serde tests pass. No compile errors from the added `typed_data: None` fields.

- [ ] **Step 6: Commit**

```bash
git add ows/crates/ows-core/src/policy.rs ows/crates/ows-lib/src/key_ops.rs ows/crates/ows-lib/src/policy_engine.rs
git commit -m "feat: add TypedDataContext and typed_data field to PolicyContext"
```

---

### Task 2: Add `AllowedTypedDataContracts` policy rule

**Files:**
- Modify: `ows/crates/ows-core/src/policy.rs`
- Modify: `ows/crates/ows-lib/src/policy_engine.rs`

- [ ] **Step 1: Write failing tests for the new rule evaluation**

In `ows/crates/ows-lib/src/policy_engine.rs`, add these tests to the existing `mod tests` block. You will need to add `use ows_core::policy::TypedDataContext;` to the test imports (line 188):

```rust
    use ows_core::policy::TypedDataContext;

    fn typed_data_context(verifying_contract: Option<&str>) -> TypedDataContext {
        TypedDataContext {
            verifying_contract: verifying_contract.map(String::from),
            domain_chain_id: Some(8453),
            primary_type: "PermitSingle".into(),
            domain_name: Some("Permit2".into()),
            domain_version: Some("1".into()),
            raw_json: "{}".into(),
        }
    }

    // --- AllowedTypedDataContracts ---

    #[test]
    fn allowed_typed_data_contracts_matching_allows() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some(
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        )));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_non_matching_denies() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some("0xDEAD")));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("not in allowed list"));
    }

    #[test]
    fn allowed_typed_data_contracts_case_insensitive() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some(
            "0x000000000022d473030f116ddee9f6b43ac78ba3",
        )));
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_no_typed_data_passes() {
        let ctx = base_context(); // typed_data is None
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }

    #[test]
    fn allowed_typed_data_contracts_no_verifying_contract_denies() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(None)); // domain omits verifyingContract
        let policy = policy_with_rules(
            "td",
            vec![PolicyRule::AllowedTypedDataContracts {
                contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
            }],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(!result.allow);
        assert!(result.reason.unwrap().contains("no verifyingContract"));
    }

    #[test]
    fn combined_rules_with_typed_data_contracts() {
        let mut ctx = base_context();
        ctx.typed_data = Some(typed_data_context(Some(
            "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        )));
        let policy = policy_with_rules(
            "combined",
            vec![
                PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".into()],
                },
                PolicyRule::AllowedTypedDataContracts {
                    contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
                },
                PolicyRule::ExpiresAt {
                    timestamp: "2027-01-01T00:00:00Z".into(),
                },
            ],
        );
        let result = evaluate_policies(&[policy], &ctx);
        assert!(result.allow);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/gustavo/apps/ows-core && cargo test -p ows-lib policy_engine`

Expected: Compile error — `AllowedTypedDataContracts` is not a variant of `PolicyRule`.

- [ ] **Step 3: Add `AllowedTypedDataContracts` variant to `PolicyRule`**

In `ows/crates/ows-core/src/policy.rs`, add the new variant to the `PolicyRule` enum (after line 18):

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRule {
    /// Deny if `chain_id` is not in the allowlist.
    AllowedChains { chain_ids: Vec<String> },

    /// Deny if current time is past the timestamp.
    ExpiresAt { timestamp: String },

    /// Deny typed data signing if `domain.verifyingContract` is not in the allowlist.
    /// Passes through for non-typed-data signing operations.
    AllowedTypedDataContracts { contracts: Vec<String> },
}
```

- [ ] **Step 4: Add the match arm and evaluation function in `policy_engine.rs`**

In `ows/crates/ows-lib/src/policy_engine.rs`, update `evaluate_rule` (line 40) to handle the new variant:

```rust
fn evaluate_rule(rule: &PolicyRule, policy_id: &str, ctx: &PolicyContext) -> PolicyResult {
    match rule {
        PolicyRule::AllowedChains { chain_ids } => eval_allowed_chains(policy_id, chain_ids, ctx),
        PolicyRule::ExpiresAt { timestamp } => eval_expires_at(policy_id, timestamp, ctx),
        PolicyRule::AllowedTypedDataContracts { contracts } => {
            eval_allowed_typed_data_contracts(policy_id, contracts, ctx)
        }
    }
}
```

Add the evaluation function after `eval_expires_at` (after line 65):

```rust
fn eval_allowed_typed_data_contracts(
    policy_id: &str,
    contracts: &[String],
    ctx: &PolicyContext,
) -> PolicyResult {
    let td = match &ctx.typed_data {
        None => return PolicyResult::allowed(), // not a typed data signing call
        Some(td) => td,
    };

    let contract = match &td.verifying_contract {
        None => {
            return PolicyResult::denied(
                policy_id,
                "typed data has no verifyingContract but policy requires one",
            );
        }
        Some(c) => c,
    };

    let contract_lower = contract.to_lowercase();
    if contracts
        .iter()
        .any(|c| c.to_lowercase() == contract_lower)
    {
        PolicyResult::allowed()
    } else {
        PolicyResult::denied(
            policy_id,
            format!("verifyingContract {contract} not in allowed list"),
        )
    }
}
```

- [ ] **Step 5: Add serde test for the new rule variant**

In `ows/crates/ows-core/src/policy.rs`, add to the existing `mod tests` block:

```rust
    #[test]
    fn test_policy_rule_serde_allowed_typed_data_contracts() {
        let rule = PolicyRule::AllowedTypedDataContracts {
            contracts: vec!["0x000000000022D473030F116dDEE9F6B43aC78BA3".into()],
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["type"], "allowed_typed_data_contracts");
        assert_eq!(json["contracts"][0], "0x000000000022D473030F116dDEE9F6B43aC78BA3");

        let deserialized: PolicyRule = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized, rule);
    }
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/gustavo/apps/ows-core && cargo test -p ows-core -p ows-lib`

Expected: All tests pass — existing tests + new serde test + all 6 new policy engine tests.

- [ ] **Step 7: Commit**

```bash
git add ows/crates/ows-core/src/policy.rs ows/crates/ows-lib/src/policy_engine.rs
git commit -m "feat: add AllowedTypedDataContracts declarative policy rule"
```

---

### Task 3: Add `sign_typed_data_with_api_key` function

**Files:**
- Modify: `ows/crates/ows-lib/src/key_ops.rs`

- [ ] **Step 1: Write the integration test**

In `ows/crates/ows-lib/src/key_ops.rs`, add these tests to the existing `mod tests` block. You will need to add `use ows_core::policy::TypedDataContext;` to the test imports at the top of the test module:

```rust
    /// Standard EIP-712 typed data JSON for testing (Permit2 PermitSingle).
    fn test_typed_data_json() -> String {
        serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "PermitSingle": [
                    {"name": "spender", "type": "address"},
                    {"name": "value", "type": "uint256"}
                ]
            },
            "primaryType": "PermitSingle",
            "domain": {
                "name": "Permit2",
                "chainId": "8453",
                "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            },
            "message": {
                "spender": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C",
                "value": "1000000"
            }
        })
        .to_string()
    }

    fn setup_typed_data_policy(vault: &Path) -> String {
        let policy = ows_core::Policy {
            id: "td-policy".to_string(),
            name: "Typed Data Policy".to_string(),
            version: 1,
            created_at: "2026-03-22T10:00:00Z".to_string(),
            rules: vec![
                PolicyRule::AllowedChains {
                    chain_ids: vec!["eip155:8453".to_string()],
                },
                PolicyRule::AllowedTypedDataContracts {
                    contracts: vec![
                        "0x000000000022D473030F116dDEE9F6B43aC78BA3".to_string(),
                    ],
                },
            ],
            executable: None,
            config: None,
            action: PolicyAction::Deny,
        };
        policy_store::save_policy(&policy, Some(vault)).unwrap();
        policy.id
    }

    #[test]
    fn sign_typed_data_with_api_key_happy_path() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_typed_data_policy(&vault);

        let (token, _) = create_api_key(
            "td-agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let result = sign_typed_data_with_api_key(
            &token,
            "test-wallet",
            &chain,
            &test_typed_data_json(),
            None,
            Some(&vault),
        );

        assert!(result.is_ok(), "sign_typed_data_with_api_key failed: {:?}", result.err());
        let sign_result = result.unwrap();
        assert!(!sign_result.signature.is_empty());
        // EIP-712 signatures have v = 27 or 28
        let v = sign_result.recovery_id.unwrap();
        assert!(v == 27 || v == 28, "unexpected v value: {v}");
    }

    #[test]
    fn sign_typed_data_with_api_key_non_evm_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("solana").unwrap();
        let result = sign_typed_data_with_api_key(
            &token,
            "test-wallet",
            &chain,
            &test_typed_data_json(),
            None,
            Some(&vault),
        );

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("EVM"));
    }

    #[test]
    fn sign_typed_data_with_api_key_wrong_contract_denied() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_typed_data_policy(&vault); // allows only Permit2 contract

        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        // Typed data with a different verifyingContract
        let wrong_contract_td = serde_json::json!({
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Order": [
                    {"name": "maker", "type": "address"}
                ]
            },
            "primaryType": "Order",
            "domain": {
                "name": "Seaport",
                "verifyingContract": "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"
            },
            "message": {
                "maker": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C"
            }
        })
        .to_string();

        let chain = ows_core::parse_chain("base").unwrap();
        let result = sign_typed_data_with_api_key(
            &token,
            "test-wallet",
            &chain,
            &wrong_contract_td,
            None,
            Some(&vault),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::Core(OwsError::PolicyDenied { reason, .. }) => {
                assert!(reason.contains("not in allowed list"));
            }
            other => panic!("expected PolicyDenied, got: {other}"),
        }
    }

    #[test]
    fn sign_typed_data_with_api_key_malformed_json_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let result = sign_typed_data_with_api_key(
            &token,
            "test-wallet",
            &chain,
            "not valid json",
            None,
            Some(&vault),
        );

        assert!(result.is_err());
    }

    #[test]
    fn sign_typed_data_with_api_key_expired_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            Some("2020-01-01T00:00:00Z"),
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let result = sign_typed_data_with_api_key(
            &token,
            "test-wallet",
            &chain,
            &test_typed_data_json(),
            None,
            Some(&vault),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::Core(OwsError::ApiKeyExpired { .. }) => {}
            other => panic!("expected ApiKeyExpired, got: {other}"),
        }
    }

    #[test]
    fn sign_typed_data_with_api_key_wallet_not_in_scope() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().to_path_buf();
        let passphrase = "test-pass";

        let wallet_id = setup_test_wallet(&vault, passphrase);
        let policy_id = setup_test_policy(&vault);

        // Create second wallet
        let mnemonic2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        let envelope2 = encrypt(mnemonic2.as_bytes(), passphrase).unwrap();
        let crypto2 = serde_json::to_value(&envelope2).unwrap();
        let wallet2 = EncryptedWallet::new(
            "wallet-2-id".to_string(),
            "other-wallet".to_string(),
            vec![],
            crypto2,
            KeyType::Mnemonic,
        );
        vault::save_encrypted_wallet(&wallet2, Some(&vault)).unwrap();

        // API key scoped to first wallet only
        let (token, _) = create_api_key(
            "agent",
            &[wallet_id],
            &[policy_id],
            passphrase,
            None,
            Some(&vault),
        )
        .unwrap();

        let chain = ows_core::parse_chain("base").unwrap();
        let result = sign_typed_data_with_api_key(
            &token,
            "other-wallet",
            &chain,
            &test_typed_data_json(),
            None,
            Some(&vault),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            OwsLibError::InvalidInput(msg) => {
                assert!(msg.contains("does not have access"));
            }
            other => panic!("expected InvalidInput, got: {other}"),
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/gustavo/apps/ows-core && cargo test -p ows-lib key_ops`

Expected: Compile error — `sign_typed_data_with_api_key` function does not exist.

- [ ] **Step 3: Implement `sign_typed_data_with_api_key`**

In `ows/crates/ows-lib/src/key_ops.rs`, add the function after `sign_message_with_api_key` (after line 206). You need to add `use ows_signer::eip712;` to the imports at the top of the file:

```rust
/// Sign EIP-712 typed data using an API token (agent mode).
///
/// EVM-only. Parses the typed data JSON before policy evaluation so that
/// the structured `TypedDataContext` is available to declarative rules and
/// executable policies.
pub fn sign_typed_data_with_api_key(
    token: &str,
    wallet_name_or_id: &str,
    chain: &ows_core::Chain,
    typed_data_json: &str,
    index: Option<u32>,
    vault_path: Option<&Path>,
) -> Result<crate::types::SignResult, OwsLibError> {
    // 1. EVM-only gate — cheapest check first
    if chain.chain_type != ows_core::ChainType::Evm {
        return Err(OwsLibError::InvalidInput(
            "EIP-712 typed data signing is only supported for EVM chains".into(),
        ));
    }

    // 2. Token lookup
    let token_hash = key_store::hash_token(token);
    let key_file = key_store::load_api_key_by_token_hash(&token_hash, vault_path)?;

    // 3. Expiry check
    check_expiry(&key_file)?;

    // 4. Wallet scope check
    let wallet = vault::load_wallet_by_name_or_id(wallet_name_or_id, vault_path)?;
    if !key_file.wallet_ids.contains(&wallet.id) {
        return Err(OwsLibError::InvalidInput(format!(
            "API key '{}' does not have access to wallet '{}'",
            key_file.name, wallet.id,
        )));
    }

    // 5. Parse typed data early — validates JSON and extracts domain fields
    let parsed = eip712::parse_typed_data(typed_data_json)?;

    // 6. Build PolicyContext with TypedDataContext
    let policies = load_policies_for_key(&key_file, vault_path)?;
    let now = chrono::Utc::now();
    let date = now.format("%Y-%m-%d").to_string();

    let typed_data_ctx = ows_core::policy::TypedDataContext {
        verifying_contract: parsed
            .domain
            .get("verifyingContract")
            .and_then(|v| v.as_str())
            .map(String::from),
        domain_chain_id: parsed
            .domain
            .get("chainId")
            .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64())),
        primary_type: parsed.primary_type.clone(),
        domain_name: parsed
            .domain
            .get("name")
            .and_then(|v| v.as_str())
            .map(String::from),
        domain_version: parsed
            .domain
            .get("version")
            .and_then(|v| v.as_str())
            .map(String::from),
        raw_json: typed_data_json.to_string(),
    };

    let context = ows_core::PolicyContext {
        chain_id: chain.chain_id.to_string(),
        wallet_id: wallet.id.clone(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: hex::encode(typed_data_json.as_bytes()),
            data: None,
        },
        spending: noop_spending_context(&date),
        timestamp: now.to_rfc3339(),
        typed_data: Some(typed_data_ctx),
    };

    // 7. Evaluate policies
    let result = policy_engine::evaluate_policies(&policies, &context);
    if !result.allow {
        return Err(OwsLibError::Core(OwsError::PolicyDenied {
            policy_id: result.policy_id.unwrap_or_default(),
            reason: result.reason.unwrap_or_else(|| "denied".into()),
        }));
    }

    // 8. Decrypt key and sign
    let key = decrypt_key_from_api_key(&key_file, &wallet.id, token, chain.chain_type, index)?;
    let evm_signer = ows_signer::chains::EvmSigner;
    let output = evm_signer.sign_typed_data(key.expose(), typed_data_json)?;

    Ok(crate::types::SignResult {
        signature: hex::encode(&output.signature),
        recovery_id: output.recovery_id,
    })
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/gustavo/apps/ows-core && cargo test -p ows-lib key_ops`

Expected: All existing key_ops tests pass + all 6 new typed data tests pass.

- [ ] **Step 5: Commit**

```bash
git add ows/crates/ows-lib/src/key_ops.rs
git commit -m "feat: add sign_typed_data_with_api_key function"
```

---

### Task 4: Remove hard-blocks and wire up the dispatcher

**Files:**
- Modify: `ows/crates/ows-lib/src/ops.rs:506-511`
- Modify: `ows/crates/ows-cli/src/commands/sign_message.rs:21-25`

- [ ] **Step 1: Replace the hard-block in `ops.rs`**

In `ows/crates/ows-lib/src/ops.rs`, replace lines 506-511:

Old code:
```rust
    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        return Err(OwsLibError::InvalidInput(
            "EIP-712 typed data signing via API key is not yet supported; use sign_transaction"
                .into(),
        ));
    }
```

New code:
```rust
    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        return crate::key_ops::sign_typed_data_with_api_key(
            credential,
            wallet,
            &chain,
            typed_data_json,
            index,
            vault_path,
        )
        .map(|r| SignResult {
            signature: r.signature,
            recovery_id: r.recovery_id,
        });
    }
```

Note: Check whether the `SignResult` type returned by `key_ops::sign_typed_data_with_api_key` is the same type as `ops::SignResult`. They may be the same type (`crate::types::SignResult`) — if so the `.map()` is unnecessary and you can return directly. Verify by checking the return type of `sign_typed_data` in `ops.rs` (line 496) and `sign_typed_data_with_api_key` in `key_ops.rs`. If they are the same type, simplify to:

```rust
    if credential.starts_with(crate::key_store::TOKEN_PREFIX) {
        return crate::key_ops::sign_typed_data_with_api_key(
            credential,
            wallet,
            &chain,
            typed_data_json,
            index,
            vault_path,
        );
    }
```

- [ ] **Step 2: Remove the CLI guard and add delegation in `sign_message.rs`**

In `ows/crates/ows-cli/src/commands/sign_message.rs`, replace lines 21-25:

Old code:
```rust
        if typed_data.is_some() {
            return Err(CliError::InvalidArgs(
                "EIP-712 typed data signing via API key is not yet supported".into(),
            ));
        }
```

New code:
```rust
        if let Some(td_json) = typed_data {
            let result = ows_lib::sign_typed_data(
                wallet_name,
                chain_str,
                td_json,
                passphrase.as_deref(),
                Some(index),
                None,
            )?;
            return print_result(&result.signature, result.recovery_id, json_output);
        }
```

- [ ] **Step 3: Update the doc comment on `sign_typed_data` in `ops.rs`**

In `ows/crates/ows-lib/src/ops.rs`, replace the doc comment at lines 484-488:

Old:
```rust
/// Sign EIP-712 typed structured data. Returns hex-encoded signature.
/// Only supported for EVM chains.
///
/// Note: API token signing is not supported for typed data (EVM-specific
/// operation that requires full context). Use `sign_transaction` instead.
```

New:
```rust
/// Sign EIP-712 typed structured data. Returns hex-encoded signature.
/// Only supported for EVM chains.
///
/// Accepts either the owner's passphrase or an API token (`ows_key_...`).
/// When a token is provided, policy enforcement occurs before signing.
```

- [ ] **Step 4: Build and run all tests**

Run: `cd /Users/gustavo/apps/ows-core && cargo test`

Expected: Full test suite passes. The existing `sign_typed_data` tests via owner path still work. The new `sign_typed_data_with_api_key` tests still pass through the new dispatcher path.

- [ ] **Step 5: Commit**

```bash
git add ows/crates/ows-lib/src/ops.rs ows/crates/ows-cli/src/commands/sign_message.rs
git commit -m "feat: enable EIP-712 typed data signing via API key"
```

---

### Task 5: Update documentation

**Files:**
- Modify: `docs/sdk-node.md`
- Modify: `docs/sdk-python.md`
- Modify: `docs/03-policy-engine.md`

- [ ] **Step 1: Remove "not yet supported" note in Node.js SDK docs**

In `docs/sdk-node.md`, find and remove the line (around line 267):
```
API-token typed-data signing is not yet supported.
```

- [ ] **Step 2: Remove "not yet supported" note in Python SDK docs**

In `docs/sdk-python.md`, find and remove the line (around line 225):
```
API-token typed-data signing is not yet supported.
```

- [ ] **Step 3: Add `AllowedTypedDataContracts` rule documentation**

In `docs/03-policy-engine.md`, find the section documenting declarative rules (where `AllowedChains` and `ExpiresAt` are documented). Add a new subsection:

```markdown
### `allowed_typed_data_contracts`

Restricts which smart contracts an API key can sign EIP-712 typed data for. The rule checks the `domain.verifyingContract` field of the typed data against a whitelist of addresses.

```json
{
  "type": "allowed_typed_data_contracts",
  "contracts": ["0x000000000022D473030F116dDEE9F6B43aC78BA3"]
}
```

**Behavior:**
- For `sign_message` and `sign_transaction` calls, this rule **passes through** (does not restrict).
- For `sign_typed_data` calls where the domain includes a `verifyingContract`, the address must be in the `contracts` list (case-insensitive comparison).
- For `sign_typed_data` calls where the domain **omits** `verifyingContract`, the rule **denies** — the contract cannot be verified.

**Example policy:**
```json
{
  "id": "permit2-only",
  "name": "Restrict to Permit2 typed data",
  "version": 1,
  "created_at": "2026-03-30T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453"] },
    { "type": "allowed_typed_data_contracts", "contracts": ["0x000000000022D473030F116dDEE9F6B43aC78BA3"] }
  ],
  "action": "deny"
}
```
```

- [ ] **Step 4: Add `TypedDataContext` documentation**

In `docs/03-policy-engine.md`, find the section documenting `PolicyContext` (the JSON schema sent to executable policies). Add the new field:

```markdown
### `typed_data` (optional)

Present only for `sign_typed_data` calls. Omitted entirely for `sign_message` and `sign_transaction`.

```json
{
  "typed_data": {
    "verifying_contract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    "domain_chain_id": 8453,
    "primary_type": "PermitSingle",
    "domain_name": "Permit2",
    "domain_version": "1",
    "raw_json": "{...full EIP-712 JSON...}"
  }
}
```

All fields except `primary_type` and `raw_json` are optional (the EIP-712 domain can omit any field). Executable policies can use `raw_json` to inspect the full typed data structure including message fields.
```

- [ ] **Step 5: Commit**

```bash
git add docs/sdk-node.md docs/sdk-python.md docs/03-policy-engine.md
git commit -m "docs: document EIP-712 API key signing and AllowedTypedDataContracts rule"
```

---

### Task 6: Binding-level smoke tests

**Files:**
- Modify: `bindings/node/__test__/index.spec.mjs`
- Modify: `bindings/python/tests/test_bindings.py`

- [ ] **Step 1: Add Node.js test for `signTypedData` with API key**

In `bindings/node/__test__/index.spec.mjs`, add the `signTypedData` import if not already present, then add a test. First read the existing test file to find the test structure and existing imports, then add:

```javascript
test('signTypedData with API key token succeeds', async () => {
  // Use the same vault and wallet setup as existing API key tests
  // Create a policy allowing Base chain
  const policyJson = JSON.stringify({
    id: 'td-test-policy',
    name: 'TD Test',
    version: 1,
    created_at: '2026-03-22T10:00:00Z',
    rules: [
      { type: 'allowed_chains', chain_ids: ['eip155:8453'] },
    ],
    action: 'deny',
  });
  createPolicy(policyJson, vaultPath);

  // Create API key with that policy
  const { token } = createApiKey(
    'td-agent',
    [walletId],
    ['td-test-policy'],
    passphrase,
    undefined,
    vaultPath,
  );

  const typedData = JSON.stringify({
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Mail: [{ name: 'contents', type: 'string' }],
    },
    primaryType: 'Mail',
    domain: {
      name: 'Test',
      verifyingContract: '0x000000000022D473030F116dDEE9F6B43aC78BA3',
    },
    message: { contents: 'Hello' },
  });

  const result = signTypedData('test-wallet', 'base', typedData, token, undefined, vaultPath);
  expect(result.signature).toBeTruthy();
  expect(result.signature.length).toBeGreaterThan(0);
});
```

Note: Adapt this test to match the exact test setup pattern used in the existing tests — read the file first to match variable names, vault setup, and assertion style.

- [ ] **Step 2: Add Python test for `sign_typed_data` with API key**

In `bindings/python/tests/test_bindings.py`, add a similar test following the existing test patterns in that file:

```python
def test_sign_typed_data_with_api_key(tmp_path):
    """EIP-712 typed data signing via API key token."""
    vault = str(tmp_path)
    passphrase = "test-pass"

    # Setup wallet (follow existing pattern in the file)
    wallet_id = setup_wallet(vault, passphrase)

    # Create policy
    policy_json = json.dumps({
        "id": "td-test-policy",
        "name": "TD Test",
        "version": 1,
        "created_at": "2026-03-22T10:00:00Z",
        "rules": [
            {"type": "allowed_chains", "chain_ids": ["eip155:8453"]},
        ],
        "action": "deny",
    })
    ows.create_policy(policy_json, vault)

    # Create API key
    token, _ = ows.create_api_key(
        "td-agent", [wallet_id], ["td-test-policy"], passphrase, None, vault
    )

    typed_data = json.dumps({
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "Mail": [{"name": "contents", "type": "string"}],
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Test",
            "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
        },
        "message": {"contents": "Hello"},
    })

    result = ows.sign_typed_data("test-wallet", "base", typed_data, token, None, vault)
    assert result["signature"]
    assert len(result["signature"]) > 0
```

Note: Adapt this test to match the exact test setup pattern in the existing Python tests — read the file first to match helper functions, imports, and assertion style.

- [ ] **Step 3: Run binding tests**

Run Node.js tests:
```bash
cd /Users/gustavo/apps/ows-core/bindings/node && npm test
```

Run Python tests:
```bash
cd /Users/gustavo/apps/ows-core/bindings/python && python -m pytest tests/
```

Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add bindings/node/__test__/index.spec.mjs bindings/python/tests/test_bindings.py
git commit -m "test: add binding-level smoke tests for EIP-712 API key signing"
```
