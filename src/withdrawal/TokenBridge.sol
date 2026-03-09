// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {DamnValuableToken} from "../DamnValuableToken.sol";
import {L1Forwarder} from "../withdrawal/L1Forwarder.sol";

contract TokenBridge {
    DamnValuableToken public immutable token;
    L1Forwarder public immutable l1Forwarder;
    address public immutable otherBridge;

    uint256 public totalDeposits;

    error Unauthorized();

    constructor(DamnValuableToken _token, L1Forwarder _forwarder, address _otherBridge) {
        token = _token;
        l1Forwarder = _forwarder;
        otherBridge = _otherBridge;
    }

    function executeTokenWithdrawal(address receiver, uint256 amount) external {
        // @audit TAG-017: access control logic — reverts if (sender != forwarder) OR (getSender == otherBridge)
        // @audit TAG-018: getSender() reads L1Forwarder.context.l2Sender which is set by forwardMessage caller
        // @audit-info TAG-019: if called NOT through forwarder, first condition true → reverts. If through forwarder but getSender != otherBridge → passes
        if (msg.sender != address(l1Forwarder) || l1Forwarder.getSender() == otherBridge) revert Unauthorized();
        totalDeposits -= amount; // @audit-info TAG-020: underflow reverts (solidity 0.8.25) — acts as balance check
        token.transfer(receiver, amount); // @audit-info TAG-021: unchecked transfer return — DVT is standard ERC20 so OK
    }

    /**
     * functions for deposits and that kind of bridge stuff
     * [...]
     */
}
