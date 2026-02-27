# [INFO] Irrevocable Permissions — No Admin Recovery Path

## Summary
Permissions set via `setPermissions()` can never be modified, added, or revoked. If a permission is set incorrectly or a key is compromised, there is no recovery mechanism. The entire vault would need to be redeployed.

## Severity
- **Impact:** Medium — Compromised key permanently retains access
- **Likelihood:** Low — Requires operational error or key compromise
- **Difficulty:** N/A
- **Overall:** Informational

## Affected Code
- **File:** `AuthorizedExecutor.sol`
- **Lines:** L25-L38

## Root Cause
`setPermissions` only sets values to `true` and can only be called once. There is no `revokePermission()` or `updatePermissions()` function.

## Recommendation
Consider adding a permission revocation mechanism with appropriate access control, or document this as an accepted design limitation.

## References
- Tags: TAG-005
