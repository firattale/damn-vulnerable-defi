# Audit Tags — abi-smuggling

## Summary
- Total tags: 14
- @audit:security: 4
- @audit:math: 0
- @audit:logic: 2
- @audit:edge: 3
- @audit:question: 1
- @audit:knob: 4

## Hot Spot Analysis
| Contract | Security | Math | Logic | Edge | Question | Knob | Total |
|----------|----------|------|-------|------|----------|------|-------|
| AuthorizedExecutor.sol | 4 | 0 | 1 | 2 | 1 | 3 | 11 |
| SelfAuthorizedVault.sol | 0 | 0 | 1 | 1 | 0 | 1 | 3 |

## Tags by Contract

### AuthorizedExecutor.sol

#### [TAG-001] @audit:security — Hardcoded calldata offset ignores ABI dynamic offset pointer
- **Lines:** L49-L52
- **Code:**
  ```solidity
  uint256 calldataOffset = 4 + 32 * 3; // calldata position where `actionData` begins
  assembly {
      selector := calldataload(calldataOffset)
  }
  ```
- **Observation:** The selector is read from a hardcoded calldata position (byte 100), which assumes the `bytes calldata actionData` parameter's ABI offset pointer is always `0x40` (64). The ABI spec allows the offset pointer to be any valid value. If an attacker provides a non-standard offset (e.g., `0x80`), Solidity's ABI decoder follows the pointer to a different location, while the assembly still reads byte 100. This creates a divergence between the checked selector and the executed selector.

#### [TAG-002] @audit:security — Permission check uses potentially spoofed selector
- **Lines:** L54-L56
- **Code:**
  ```solidity
  if (!permissions[getActionId(selector, msg.sender, target)]) {
      revert NotAllowed();
  }
  ```
- **Observation:** The `selector` variable comes from the hardcoded calldata read in TAG-001. If TAG-001's selector diverges from the actual `actionData` content, this permission check verifies authorization for a DIFFERENT function than what gets executed on L60.

#### [TAG-003] @audit:security — Actual call uses Solidity-decoded actionData, not assembly-read selector
- **Lines:** L58-L60
- **Code:**
  ```solidity
  _beforeFunctionCall(target, actionData);
  return target.functionCall(actionData);
  ```
- **Observation:** `actionData` here is the Solidity-decoded parameter, which follows the ABI offset pointer — NOT the hardcoded byte 100 position. This means `functionCall` executes whatever the offset pointer points to, regardless of what the assembly read at byte 100. TAG-001 + TAG-002 + TAG-003 together form a complete authorization bypass: the check reads one selector, the call executes another.

#### [TAG-004] @audit:security — No access control on setPermissions
- **Lines:** L25-L28
- **Code:**
  ```solidity
  function setPermissions(bytes32[] memory ids) external {
      if (initialized) {
          revert AlreadyInitialized();
      }
  ```
- **Observation:** Any address can call `setPermissions` if it is the first caller. There is no `onlyOwner` or deployer check. In the test setup, the deployer calls it in the same transaction flow, but in a real deployment, front-running could hijack initialization.

#### [TAG-005] @audit:logic — Permissions are write-once, append-only, irrevocable
- **Lines:** L30-L36
- **Code:**
  ```solidity
  for (uint256 i = 0; i < ids.length;) {
      unchecked {
          permissions[ids[i]] = true;
          ++i;
      }
  }
  initialized = true;
  ```
- **Observation:** Permissions can only be set to `true`, never to `false`. Once initialized, no permissions can be added, removed, or modified. This is permanent and immutable — there is no admin recovery path.

#### [TAG-006] @audit:edge — Empty permission array still locks initialization
- **Lines:** L30-L36
- **Code:**
  ```solidity
  for (uint256 i = 0; i < ids.length;) { ... }
  initialized = true;
  ```
- **Observation:** If `setPermissions` is called with an empty array, the loop body never executes (no permissions set), but `initialized` is still set to `true`. This permanently locks the contract with zero permissions — a bricking scenario.

#### [TAG-007] @audit:edge — calldataOffset assumes exactly 2 parameters before dynamic data
- **Lines:** L49
- **Code:**
  ```solidity
  uint256 calldataOffset = 4 + 32 * 3; // calldata position where `actionData` begins
  ```
- **Observation:** The comment says "calldata position where `actionData` begins" but this is only true for standard ABI encoding where the offset pointer is `0x40`. The value `4 + 32*3 = 100` skips: 4 (selector) + 32 (target) + 32 (offset pointer) + 32 (length) = 100. If any of these assumptions change (e.g., extra calldata appended, non-standard offset), byte 100 may not contain the actionData selector.

#### [TAG-008] @audit:question — Why use assembly for selector extraction instead of Solidity?
- **Lines:** L47-L52
- **Code:**
  ```solidity
  bytes4 selector;
  uint256 calldataOffset = 4 + 32 * 3;
  assembly {
      selector := calldataload(calldataOffset)
  }
  ```
- **Observation:** The selector could be safely extracted using `bytes4(actionData[:4])` in pure Solidity, which would always match the actual `actionData` parameter. The use of raw assembly with a hardcoded offset introduces a discrepancy between what is checked and what is executed. This is either a deliberate design choice or a bug — the challenge name "ABI Smuggling" strongly suggests it's the intended vulnerability.

#### [TAG-009] @audit:knob — ABI offset pointer is attacker-controlled
- **Lines:** L46 (function signature)
- **Code:**
  ```solidity
  function execute(address target, bytes calldata actionData) external ...
  ```
- **Knob Note:** The caller constructs the entire calldata for `execute()`. The ABI encoding of a `bytes` parameter includes an offset pointer (word 2 in calldata, bytes 36-67). This offset is NOT validated — the attacker can set it to any value. Solidity's decoder will follow whatever offset is provided to locate `actionData`, while the assembly reads from a fixed position.

#### [TAG-010] @audit:knob — Attacker controls bytes at hardcoded position 100
- **Lines:** L49-L52
- **Code:**
  ```solidity
  uint256 calldataOffset = 4 + 32 * 3;
  assembly {
      selector := calldataload(calldataOffset)
  }
  ```
- **Knob Note:** By manipulating the ABI offset pointer (TAG-009) to point past byte 100, the attacker can place arbitrary bytes at position 100 that are NOT part of the actual `actionData`. They can place an authorized selector (e.g., `withdraw`'s `0xd9caed12`) at byte 100 to pass the permission check, while the real `actionData` at the offset-specified location contains a different selector (e.g., `sweepFunds`'s `0x85fb709d`).

#### [TAG-011] @audit:knob — Permission for withdraw selector granted to player
- **Lines:** (from test setup, relevant to exploit)
- **Code:**
  ```solidity
  // Test setup: player has permission for withdraw (0xd9caed12)
  bytes32 playerPermission = vault.getActionId(hex"d9caed12", player, address(vault));
  ```
- **Knob Note:** The player has a legitimate permission for the `withdraw` selector. Combined with TAG-009 and TAG-010, the player can pass the permission check using the `withdraw` selector while actually executing `sweepFunds`. This is the access knob that enables the smuggling attack.

### SelfAuthorizedVault.sol

#### [TAG-012] @audit:logic — onlyThis modifier is the sole access control for critical functions
- **Lines:** L20-L25, L33, L47
- **Code:**
  ```solidity
  modifier onlyThis() {
      if (msg.sender != address(this)) {
          revert CallerNotAllowed();
      }
      _;
  }
  ```
- **Observation:** Both `withdraw` and `sweepFunds` rely solely on `onlyThis`. Since `execute()` calls `target.functionCall(actionData)` where target is `address(this)`, the vault calls itself, satisfying `onlyThis`. This means `onlyThis` does NOT provide independent access control — it only ensures calls come through the `execute()` dispatcher. If the execute dispatcher's authorization is bypassed (TAG-001 through TAG-003), `onlyThis` provides no additional protection.

#### [TAG-013] @audit:edge — Timestamp boundary is exclusive (uses <= not <)
- **Lines:** L38-L40
- **Code:**
  ```solidity
  if (block.timestamp <= _lastWithdrawalTimestamp + WAITING_PERIOD) {
      revert WithdrawalWaitingPeriodNotEnded();
  }
  ```
- **Observation:** The check uses `<=`, meaning the withdrawal is only allowed when `block.timestamp > _lastWithdrawalTimestamp + WAITING_PERIOD` (strictly greater). At the exact boundary timestamp, withdrawal is still denied. Minor behavioral note — not a vulnerability.

#### [TAG-014] @audit:knob — sweepFunds has zero restrictions beyond onlyThis
- **Lines:** L47-L49
- **Code:**
  ```solidity
  function sweepFunds(address receiver, IERC20 token) external onlyThis {
      SafeTransferLib.safeTransfer(address(token), receiver, token.balanceOf(address(this)));
  }
  ```
- **Knob Note:** Unlike `withdraw` (which has amount limits and time restrictions), `sweepFunds` transfers the ENTIRE token balance with no cap and no cooldown. If an attacker can reach this function through the authorization bypass in TAG-001/002/003, they drain the complete vault in a single transaction.

## Knob Summary

### Access Knobs
- [TAG-011] Player has legitimate permission for `withdraw` selector — provides the authorized selector needed to smuggle past the permission check
- [TAG-004] `setPermissions` has no access control — first caller defines all permissions (not exploitable post-init)

### Amount Knobs
- [TAG-014] `sweepFunds` transfers entire balance — no amount limit means full drain if reached

### Calldata/Encoding Knobs
- [TAG-009] ABI offset pointer for `bytes calldata actionData` is attacker-controlled — determines where Solidity's decoder reads the actual data
- [TAG-010] Bytes at hardcoded position 100 are attacker-controlled — the permission check reads from here regardless of where actual data lives

### State Knobs
- [TAG-005] Permissions are permanent and irrevocable — once set, the authorization policy cannot be corrected
- [TAG-006] Empty initialization permanently bricks the contract

### Timing Knobs
- [TAG-013] Withdrawal cooldown uses strict inequality — minor, not exploitable

## Phase 2 Notes

The codebase is small (80 SLOC) but contains a critical vulnerability cluster in TAG-001/002/003. The root cause is using inline assembly to read a function selector from a hardcoded calldata position instead of extracting it from the Solidity-decoded `actionData` parameter. The ABI encoding format for dynamic types (`bytes`) includes an offset pointer that the caller controls, creating a divergence between what the permission system checks and what actually gets executed.

The attack chain is clear: TAG-009 (offset knob) + TAG-010 (content knob) + TAG-011 (access knob) + TAG-014 (impact knob) = unauthorized full vault drain.

The SelfAuthorizedVault itself is well-implemented — its `onlyThis` modifier, withdrawal limits, and target restriction in `_beforeFunctionCall` are all correct. The vulnerability is entirely in the parent `AuthorizedExecutor`'s calldata parsing.
