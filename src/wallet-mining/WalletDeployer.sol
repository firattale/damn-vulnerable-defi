// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";

/**
 * @notice A contract that allows deployers of Gnosis Safe wallets to be rewarded.
 *         Includes an optional authorization mechanism to ensure only expected accounts
 *         are rewarded for certain deployments.
 */
contract WalletDeployer {
    // Addresses of a Safe factory and copy on this chain
    SafeProxyFactory public immutable cook; // SafeProxyFactory contract for deploying Safe proxies
    address public immutable cpy; // Safe singleton implementation contract

    uint256 public constant pay = 1 ether;
    address public immutable chief; // Contract admin/deployer address
    address public immutable gem; // ERC20 token contract for payments

    address public mom; // Authorization contract address
    address public hat; // Reserved for future use

    error Boom();

    constructor(address _gem, address _cook, address _cpy, address _chief) {
        gem = _gem;
        cook = SafeProxyFactory(_cook);
        cpy = _cpy;
        chief = _chief;
    }

    /**
     * @notice Allows the chief to set an authorizer contract.
     */
    function rule(address _mom) external {
        if (msg.sender != chief || _mom == address(0) || mom != address(0)) {
            revert Boom();
        }
        mom = _mom;
    }

    /**
     * @notice Allows the caller to deploy a new Safe account and receive a payment in return.
     *         If the authorizer is set, the caller must be authorized to execute the deployment
     * @param aim Target address where the Safe should be deployed (must match CREATE2 prediction)
     * @param wat Safe initialization data containing setup parameters
     * @param num Salt nonce for CREATE2 deterministic address generation
     * @return success True if deployment succeeded and payment was made
     */
    function drop(
        address aim,
        bytes memory wat,
        uint256 num
    ) external returns (bool success) {
        // Check authorization: if authorizer is set, verify caller is authorized for target address
        if (mom != address(0) && !can(msg.sender, aim)) {
            return false;
        }

        // Deploy Safe proxy and verify it was created at the expected address
        // Uses SafeProxyFactory to create proxy pointing to Safe singleton implementation
        if (address(cook.createProxyWithNonce(cpy, wat, num)) != aim) {
            return false;
        }

        if (IERC20(gem).balanceOf(address(this)) >= pay) {
            IERC20(gem).transfer(msg.sender, pay);
        }
        return true;
    }

    /**
     * @notice Checks if user `u` is authorized to deploy at address `a`
     * @dev Uses inline assembly to call the authorizer contract stored in slot 0
     *      Calls can(address,address) function with selector 0x4538c4eb
     * @param u User address to check authorization for
     * @param a Target deployment address
     * @return y True if user is authorized for the target address
     */
    function can(address u, address a) public view returns (bool y) {
        assembly {
            let m := sload(0) // Load authorizer address from storage slot 0 (mom)
            if iszero(extcodesize(m)) {
                // Revert if authorizer has no code
                stop()
            }
            let p := mload(0x40) // Get free memory pointer
            mstore(0x40, add(p, 0x44)) // Update free memory pointer
            mstore(p, shl(0xe0, 0x4538c4eb)) // Store function selector: can(address,address)
            mstore(add(p, 0x04), u) // Store first parameter: user address
            mstore(add(p, 0x24), a) // Store second parameter: target address
            if iszero(staticcall(gas(), m, p, 0x44, p, 0x20)) {
                // Call authorizer.can(u, a)
                stop() // Revert if call failed
            }
            y := mload(p) // Load return value (boolean)
        }
    }
}
