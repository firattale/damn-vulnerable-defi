# Protocol Goals — abi-smuggling

## Protocol Summary
SelfAuthorizedVault is a token vault with an embedded generic authorization scheme (`AuthorizedExecutor`). It holds 1 million DVT tokens and restricts function execution to pre-approved (caller, selector, target) tuples. It supports limited periodic withdrawals and an emergency sweep function, both gated by a `onlyThis` modifier requiring calls to originate from the vault itself via the `execute()` dispatcher.

## Protocol Type
**Vault** with **Access Control** — A permissioned token vault that uses a custom action-authorization system to restrict which callers can invoke which functions on the vault through a generic executor pattern.

## Previous Audit Findings
No previous audits found.

## Acknowledged Risks
None documented.

## Contract Overview
| Contract | Purpose | SLOC | Key Functions |
|----------|---------|------|---------------|
| AuthorizedExecutor | Abstract base providing a permission-gated arbitrary function call dispatcher | 40 | `setPermissions`, `execute`, `getActionId` |
| SelfAuthorizedVault | Concrete vault holding tokens, restricts withdrawals by amount/time, provides emergency sweep | 40 | `withdraw`, `sweepFunds`, `getLastWithdrawalTimestamp` |

## Entry Points (State-Changing)

### AuthorizedExecutor
- `setPermissions(bytes32[] memory ids)` — Sets permission flags for action IDs. Can only be called once (guarded by `initialized` flag). No access modifier beyond the one-time guard. First caller wins.
- `execute(address target, bytes calldata actionData)` — Dispatches an arbitrary call to `target` with `actionData`, after checking the caller has permission for the extracted 4-byte selector. Modifiers: `nonReentrant`. Uses inline assembly to read selector from calldata.

### SelfAuthorizedVault
- `withdraw(address token, address recipient, uint256 amount)` — Sends up to `WITHDRAWAL_LIMIT` (1 ether) of a token to a recipient, subject to a 15-day waiting period. Modifier: `onlyThis` (msg.sender must be the vault itself).
- `sweepFunds(address receiver, IERC20 token)` — Transfers the vault's entire balance of a token to `receiver`. Modifier: `onlyThis`. No amount limit, no waiting period — emergency function.

## Entry Points (View/Pure)

### AuthorizedExecutor
- `initialized() → bool` — Whether permissions have been set.
- `permissions(bytes32) → bool` — Whether a specific action ID is allowed.
- `getActionId(bytes4 selector, address executor, address target) → bytes32` — Computes the keccak256 action ID from selector + executor + target.

### SelfAuthorizedVault
- `WITHDRAWAL_LIMIT() → uint256` — Returns 1 ether.
- `WAITING_PERIOD() → uint256` — Returns 15 days.
- `getLastWithdrawalTimestamp() → uint256` — Returns the timestamp of the last withdrawal.

## Access Control Matrix

| Role | Capabilities | Risk Level |
|------|-------------|------------|
| First caller (deployer) | Calls `setPermissions` once to define all allowed actions | **Critical** — defines the entire authorization policy permanently |
| deployer (post-init) | Authorized to call `sweepFunds` on the vault via `execute` (selector `0x85fb709d`) | **High** — can drain entire vault |
| player (post-init) | Authorized to call `withdraw` on the vault via `execute` (selector `0xd9caed12`) | **Low** — limited to 1 ETH every 15 days |
| Anyone else | No permissions | None |
| `address(this)` (vault) | Only entity that can directly call `withdraw` and `sweepFunds` via `onlyThis` | **Critical** — the self-call pattern is the trust anchor |

## Token Flow Map

```
Deployer ──transfer()──→ SelfAuthorizedVault (holds 1M DVT)
                              │
                              ├── withdraw() ──→ recipient (max 1 ETH, 15-day cooldown)
                              │                  [requires: onlyThis + permission check via execute()]
                              │
                              └── sweepFunds() ──→ receiver (entire balance)
                                                   [requires: onlyThis + permission check via execute()]
```

- **Inflows:** Direct ERC20 `transfer()` from deployer during setup. No deposit function.
- **Holdings:** All tokens held as ERC20 balance in the `SelfAuthorizedVault` contract.
- **Internal movements:** None. Single contract holds everything.
- **Outflows:** `withdraw()` (rate-limited, capped) or `sweepFunds()` (unrestricted emergency drain).
- **Minting/Burning:** None.

## Economic Model
- **Fees:** None.
- **Incentives:** None — this is a simple custodial vault.
- **Penalties:** None.
- **Value Source:** N/A — vault is purely custodial, holds deposited tokens.

The economic surface is minimal. The critical surface is **access control correctness**.

## Protocol States

| State | Valid Actions | Transitions To |
|-------|-------------|----------------|
| Uninitialized (`initialized == false`) | `setPermissions` (once) | Initialized |
| Initialized (normal operation) | `execute` (if authorized) | N/A (no pause/emergency states) |
| Withdrawal cooldown active | `execute` with `sweepFunds` only (withdraw reverts) | Cooldown expired |
| Cooldown expired (>15 days since last withdrawal) | `execute` with `withdraw` or `sweepFunds` | Cooldown active (after withdraw) |

Note: There is **no pause mechanism**, **no emergency shutdown**, and **no way to update permissions** after initialization.

## External Dependencies

| Dependency | Type | Risk |
|-----------|------|------|
| OpenZeppelin `ReentrancyGuard` | Reentrancy protection for `execute` | Low — well-audited |
| OpenZeppelin `Address.functionCall` | Safe external call with revert bubbling | Low — well-audited |
| OpenZeppelin `IERC20` | Token interface | Low — standard interface |
| Solady `SafeTransferLib` | Safe ERC20 transfer helper | Low — well-audited, handles non-standard tokens |

No oracle dependencies. No proxy patterns. No cross-protocol integrations.

## Protocol Invariants & Audit Goals

1. **Only authorized (caller, selector, target) tuples may execute actions** — The `execute()` function must correctly enforce the permission check for every call.
2. **The selector extracted from calldata must match the selector actually executed** — The assembly-based selector extraction must be correct and resistant to manipulation.
3. **`withdraw` must enforce the 1 ETH limit** — No single withdrawal can exceed `WITHDRAWAL_LIMIT`.
4. **`withdraw` must enforce the 15-day cooldown** — Cannot withdraw more frequently than `WAITING_PERIOD`.
5. **`sweepFunds` must only be callable by authorized parties** — Since it drains the entire balance, unauthorized access is catastrophic.
6. **`onlyThis` must prevent direct external calls** — `withdraw` and `sweepFunds` must only be reachable through the `execute` dispatcher.
7. **Permissions are immutable after initialization** — `setPermissions` can only be called once, and the first caller sets all permissions permanently.
8. **`_beforeFunctionCall` must enforce target == address(this)** — The vault must only allow calls to itself, not to arbitrary contracts.
9. **Reentrancy must not bypass authorization** — The `nonReentrant` guard on `execute` must prevent re-entrant permission bypass.
10. **The calldata parsing in `execute()` must be tamper-proof** — The inline assembly reading the selector at a hardcoded calldata offset must correctly correspond to the actual `actionData` being forwarded.

## Trust Assumptions

- **First caller to `setPermissions` is trusted** — They define the entire authorization policy. No ownership validation.
- **Deployer is trusted with `sweepFunds`** — Can drain the entire vault at any time via `execute`.
- **The EVM ABI encoding is standard** — The hardcoded `calldataOffset` in `execute()` assumes standard ABI encoding of the `execute(address, bytes)` call.
- **No upgradability** — Permissions and logic are immutable after deployment.

## Key Questions for Deep Dive

1. **Is the hardcoded calldata offset (`4 + 32 * 3 = 100`) correct for all valid ABI encodings of `execute(address, bytes calldata)`?** The `bytes calldata` parameter uses dynamic encoding with an offset pointer — could a caller craft calldata where the offset pointer points to a different location, causing the assembly to read a different selector than what `functionCall` actually executes?
2. **Can the `actionData` bytes parameter be ABI-encoded in a non-standard but valid way that causes the selector check and the actual call to diverge?** This is the "ABI smuggling" attack surface suggested by the challenge name.
3. **Is the `setPermissions` initialization race-free in practice?** In the test, deployer calls it in the constructor transaction context, but in general, front-running could hijack initialization.
