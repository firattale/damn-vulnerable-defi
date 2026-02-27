# Vulnerability Checklist — abi-smuggling

## Summary
- Total checks: 113
- Findings: 3 (1 critical, 1 low, 1 info)
- Passed: 22
- N/A: 85
- Notes: 3

## Stage A — Tag Classification

| Tag | Category | Classification | Finding |
|-----|----------|---------------|---------|
| TAG-001 | @audit:security | **Confirmed Vulnerability** | critical-001 |
| TAG-002 | @audit:security | **Confirmed Vulnerability** | critical-001 |
| TAG-003 | @audit:security | **Confirmed Vulnerability** | critical-001 |
| TAG-004 | @audit:security | **Confirmed Vulnerability** | low-001 |
| TAG-005 | @audit:logic | Informational | info-001 |
| TAG-006 | @audit:edge | Informational (part of low-001 scenario) | low-001 |
| TAG-007 | @audit:edge | Confirmed (same root cause as TAG-001) | critical-001 |
| TAG-008 | @audit:question | Informational (design question) | — |
| TAG-009 | @audit:knob | Knob → used in critical-001 | critical-001 |
| TAG-010 | @audit:knob | Knob → used in critical-001 | critical-001 |
| TAG-011 | @audit:knob | Knob → used in critical-001 | critical-001 |
| TAG-012 | @audit:logic | Informational (design observation) | — |
| TAG-013 | @audit:edge | False Positive (correct behavior) | — |
| TAG-014 | @audit:knob | Knob → used in critical-001 | critical-001 |

## Stage B — Knob Combination Analysis

### Combinations Tested

| Knob A | Knob B | Knob C | Amplifier | Result | Finding |
|--------|--------|--------|-----------|--------|---------|
| TAG-009 (offset) | TAG-010 (decoy) | TAG-011 (permission) | TAG-014 (impact) | **VIABLE — full vault drain** | critical-001 |
| TAG-004 (no ACL) | TAG-006 (empty init) | — | Front-running | Viable — vault bricking | low-001 |
| TAG-004 (no ACL) | TAG-005 (irrevocable) | — | Front-running | Viable — malicious perms | low-001 |
| TAG-009 (offset) | TAG-013 (timing) | — | None | Not viable — timing is irrelevant to smuggling | — |
| TAG-014 (sweepFunds) | TAG-012 (onlyThis) | — | None | Not viable alone — onlyThis correctly enforced | — |

### Amplifier Analysis
- **Flash Loans:** Not needed. Attack works with zero capital.
- **Front-running/MEV:** Not needed for critical-001. Relevant only for low-001.
- **Reentrancy:** Not viable. `nonReentrant` correctly guards `execute()`.
- **Price manipulation:** N/A. No oracles.
- **Multi-block MEV:** Not needed. Single-transaction attack.

### Common Attack Recipe Matching
| Recipe | Applicable? | Notes |
|--------|------------|-------|
| Donate + balance read | No | `sweepFunds` reads `balanceOf` but donations help attacker (they steal more) |
| Callback + stale state | No | No callbacks in token flow (standard ERC20) |
| First deposit + share inflation | No | Not a share-based vault |
| All other recipes | No | Protocol too simple — single vault, no DeFi primitives |

## Stage C — Full Vulnerability Checklist

### C1. Re-entrancy
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C1.1 | External calls before state updates | PASS | `withdraw` updates `_lastWithdrawalTimestamp` before `safeTransfer` |
| C1.2 | Cross-function re-entrancy | PASS | `nonReentrant` on `execute` prevents re-entering any flow |
| C1.3 | Cross-contract re-entrancy | N/A | Single-contract protocol |
| C1.4 | Read-only re-entrancy | N/A | No view functions used by external protocols |
| C1.5 | ERC777/ERC1155/ERC721 callback re-entrancy | N/A | DVT is standard ERC20 |
| C1.6 | Re-entrancy via receive()/fallback() | N/A | No ETH handling |
| C1.7 | ReentrancyGuard correctly applied | PASS | Applied to `execute()`, the sole entry point |

### C2. Access Control
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C2.1 | Missing access modifiers | **FINDING** | `setPermissions` has no access control (low-001) |
| C2.2 | Incorrect role/permission checks | **FINDING** | Permission check reads wrong selector (critical-001) |
| C2.3 | Default admin roles restricted | N/A | No admin role system |
| C2.4 | Privilege escalation paths | **FINDING** | Player can escalate from `withdraw` to `sweepFunds` (critical-001) |
| C2.5 | Initialization front-run | **FINDING** | `setPermissions` frontrunnable (low-001) |
| C2.6 | Owner/admin can rug users | NOTE | Deployer has `sweepFunds` permission — can drain all funds. By design. |
| C2.7 | Two-step ownership transfer | N/A | No ownership concept |

### C3. Input Validation
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C3.1 | Zero address checks | NOTE | No zero-address validation on `withdraw` recipient or `sweepFunds` receiver. Could burn tokens. Low severity (caller harms only themselves). |
| C3.2 | Zero amount checks | PASS | `withdraw` allows amount=0 but it's harmless |
| C3.3 | Array length mismatches | N/A | No multi-array functions |
| C3.4 | Bounds checking | PASS | `WITHDRAWAL_LIMIT` correctly enforced |
| C3.5 | Duplicate entries in arrays | NOTE | `setPermissions` accepts duplicates (wastes gas, no harm) |
| C3.6 | Function selector clashes | N/A | No proxy pattern |

### C4. Oracle & Price Manipulation
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C4.1-C4.9 | All oracle checks | N/A | No oracle usage |

### C5. Flash Loan Attacks
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C5.1-C5.5 | All flash loan checks | N/A | No share price, no balance-based calculations exploitable via flash loans |

### C6. Front-Running / MEV
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C6.1 | Slippage protection | N/A | No swaps |
| C6.2 | Deadline parameter | N/A | No time-sensitive operations beyond cooldown |
| C6.3 | Commit-reveal scheme | N/A | No auctions |
| C6.4 | Sandwich attack vectors | N/A | No price-impacting operations |
| C6.5 | Transaction ordering dependencies | **FINDING** | `setPermissions` ordering dependency (low-001) |

### C7. Denial of Service
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C7.1 | Unbounded loops | PASS | `setPermissions` loop bounded by input array, called once |
| C7.2 | External calls in loops | N/A | No loops with external calls |
| C7.3 | Block gas limit | PASS | Array could be large but function is called once |
| C7.4 | Dust amounts preventing withdrawal | N/A | `sweepFunds` uses `balanceOf`, handles any amount |
| C7.5 | Griefing via reverting receive/fallback | N/A | No ETH transfers |
| C7.6 | Self-destruct DoS | N/A | No ETH balance dependency |
| C7.7 | Push-over-pull | PASS | Uses pull pattern via `execute()` |
| C7.8 | Token blacklisting DoS | N/A | DVT has no blacklist |

### C8. Token & Accounting
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C8.1 | Fee-on-transfer tokens | N/A | DVT is standard; `sweepFunds` uses `balanceOf` anyway |
| C8.2 | Rebasing tokens | N/A | DVT doesn't rebase |
| C8.3 | First depositor attack | N/A | No shares |
| C8.4 | Precision loss | N/A | No division operations |
| C8.5 | Token decimal assumptions | PASS | No decimal assumptions; uses raw amounts |
| C8.6 | Return value not checked | PASS | Uses Solady `SafeTransferLib` which handles non-bool returns |
| C8.7 | approve() race condition | N/A | No approvals |
| C8.8 | Direct token transfers (donation) | PASS | `sweepFunds` uses `balanceOf`, donations just mean attacker steals more |
| C8.9 | Pausable tokens | N/A | DVT not pausable |
| C8.10 | Blocklist tokens | N/A | DVT has no blocklist |
| C8.11 | Upgradeable tokens | N/A | DVT is not a proxy |
| C8.12 | Non-bool-returning tokens | PASS | Solady `SafeTransferLib` handles this |
| C8.13 | Multiple entry point tokens | N/A | Standard ERC20 |

### C9. DeFi-Specific
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C9.1-C9.10 | All DeFi checks | N/A | Not a DeFi protocol (no AMM, lending, yield, etc.) |

### C10. Unsafe External Interactions
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C10.1 | Unchecked low-level call return values | PASS | Uses OZ `Address.functionCall` which reverts on failure |
| C10.2 | delegatecall to untrusted contracts | N/A | No delegatecall |
| C10.3 | Unsafe ecrecover | N/A | No signatures |
| C10.4 | Return data not validated | PASS | Return data passed through to caller |
| C10.5 | Contract existence check | PASS | `Address.functionCall` checks code size |

### C11. Logic & State
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C11.1 | Incorrect operator | PASS | `<=` in cooldown check is intentional (TAG-013) |
| C11.2 | Off-by-one in loops | PASS | Loop uses `< ids.length`, correct |
| C11.3 | State not updated in all paths | PASS | `_lastWithdrawalTimestamp` always updated in `withdraw` |
| C11.4 | Dead code | PASS | No dead code |
| C11.5 | Incorrect inheritance order | PASS | Simple single-inheritance chain |
| C11.6 | Constructor vs initializer | N/A | Not upgradeable |
| C11.7 | Missing events | NOTE | `withdraw` and `sweepFunds` emit no events (only ERC20 Transfer). Informational. |
| C11.8 | Enum out of bounds | N/A | No enums |
| C11.9 | Delete on struct with mapping | N/A | No struct deletion |
| C11.10 | Unsafe type casting | N/A | No explicit type casting |

### C12. Gas & EVM
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C12.1 | Unbounded gas in loops | PASS | `setPermissions` loop bounded, called once |
| C12.2 | Storage/memory/calldata misuse | PASS | `actionData` correctly uses calldata |
| C12.3 | abi.encodePacked collision | PASS | `getActionId` uses fixed-size types only (bytes4 + address + address) — no collision risk |
| C12.4 | Block properties as randomness | N/A | No randomness |
| C12.5 | Compiler version too old | PASS | Solidity 0.8.25, current |
| C12.6 | Unchecked arithmetic overflow | PASS | `unchecked { ++i }` bounded by array length |
| C12.7 | Returnbomb attack | PASS | `functionCall` returns to `execute` which returns to caller; no gas-limited subcall |
| C12.8 | Transient storage misuse | N/A | No tstore/tload |
| C12.9 | EIP-150 63/64 gas rule | PASS | `functionCall` forwards all available gas |

### C13. Upgradeability & Proxy
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C13.1-C13.8 | All proxy checks | N/A | Not an upgradeable/proxy contract |

### C14. Signature, Permit & EIP-712
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C14.1-C14.6 | All signature checks | N/A | No signature/permit functionality |

### C15. Cross-Chain & L2 Specific
| # | Check | Result | Notes |
|---|-------|--------|-------|
| C15.1-C15.5 | All cross-chain checks | N/A | No cross-chain functionality |

## Stage D — Invariant Test Suggestions

### 1. Selector Consistency Invariant
- **Property:** The selector used for permission check must ALWAYS match the first 4 bytes of the actionData actually executed
- **Catches Finding:** critical-001

```solidity
// Foundry invariant: selector checked == selector executed
// This requires a handler contract that calls execute() with various encodings
contract ExecuteHandler is Test {
    SelfAuthorizedVault vault;

    function execute_withStandardEncoding(address target, bytes calldata data) external {
        // Standard call — should work
        vault.execute(target, data);
    }

    function execute_withCustomOffset(
        address target,
        bytes4 decoySelector,
        bytes calldata realData
    ) external {
        // Craft calldata with non-standard offset
        // This should REVERT if the fix is applied, because:
        // - The selector would be read from realData[:4]
        // - Permission would be checked against realData's actual selector
        // - If caller doesn't have permission for that selector, it reverts
    }
}
```

### 2. Permission Enforcement Invariant
- **Property:** If `permissions[getActionId(selector, caller, target)] == false`, then `execute()` MUST revert
- **Catches Finding:** critical-001

```solidity
function invariant_unauthorizedCallsRevert() public {
    // For any (selector, caller, target) tuple where permissions is false,
    // calling execute with actionData starting with that selector must revert
    // This catches the case where the EXECUTED selector differs from the CHECKED one
}
```

### 3. Vault Balance Monotonicity (under legitimate use)
- **Property:** Vault balance can only decrease by at most `WITHDRAWAL_LIMIT` per `WAITING_PERIOD`
- **Catches Finding:** critical-001 (sweepFunds drains everything in one tx)

```solidity
function invariant_vaultBalanceDecreasesBounded() public {
    uint256 currentBalance = token.balanceOf(address(vault));
    uint256 maxDecrease = vault.WITHDRAWAL_LIMIT();
    // After any single authorized player action:
    assertGe(currentBalance, previousBalance - maxDecrease,
        "Balance decreased by more than WITHDRAWAL_LIMIT");
}
```

### 4. Initialization Race Regression Test
- **Property:** Only the intended deployer should set permissions
- **Catches Finding:** low-001

```solidity
function test_frontRunInitialization() public {
    SelfAuthorizedVault newVault = new SelfAuthorizedVault();

    // Attacker front-runs
    vm.prank(attacker);
    bytes32[] memory maliciousPerms = new bytes32[](1);
    maliciousPerms[0] = newVault.getActionId(hex"85fb709d", attacker, address(newVault));
    newVault.setPermissions(maliciousPerms);

    // Deployer's call reverts
    vm.prank(deployer);
    bytes32[] memory legitimatePerms = new bytes32[](1);
    legitimatePerms[0] = newVault.getActionId(hex"d9caed12", player, address(newVault));
    vm.expectRevert(AuthorizedExecutor.AlreadyInitialized.selector);
    newVault.setPermissions(legitimatePerms);
}
```
