// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {L1Gateway} from "./L1Gateway.sol";

contract L1Forwarder is ReentrancyGuard, Ownable {
    using Address for address;

    mapping(bytes32 messageId => bool seen) public successfulMessages;
    mapping(bytes32 messageId => bool seen) public failedMessages;

    L1Gateway public gateway;
    address public l2Handler;

    struct Context {
        address l2Sender;
    }

    Context public context;

    error AlreadyForwarded(bytes32 messageId);
    error BadTarget();

    constructor(L1Gateway _gateway) {
        _initializeOwner(msg.sender);
        gateway = _gateway;
    }

    function setL2Handler(address _l2Handler) external onlyOwner {
        l2Handler = _l2Handler;
    }

    function forwardMessage(uint256 nonce, address l2Sender, address target, bytes memory message)
        external
        payable
        nonReentrant
    {
        bytes32 messageId = keccak256(
            abi.encodeWithSignature("forwardMessage(uint256,address,address,bytes)", nonce, l2Sender, target, message)
        );

        // @audit TAG-009: two paths — (1) gateway+l2Handler: fresh forward, (2) anyone: retry of failed message
        if (msg.sender == address(gateway) && gateway.xSender() == l2Handler) {
            require(!failedMessages[messageId]); // @audit-info TAG-010: fresh path requires message NOT previously failed
        } else {
            require(failedMessages[messageId]); // @audit-info TAG-011: retry path requires message to have failed before
        }

        if (successfulMessages[messageId]) {
            revert AlreadyForwarded(messageId);
        }

        if (target == address(this) || target == address(gateway)) revert BadTarget(); // @audit-ok TAG-012: prevents self-call and gateway call

        Context memory prevContext = context;
        // @audit-info TAG-013: [knob] l2Sender param sets context — getSender() returns this during call
        context = Context({l2Sender: l2Sender});
        bool success;
        assembly {
            success := call(gas(), target, 0, add(message, 0x20), mload(message), 0, 0) // @audit-info TAG-014: [callback] target gets arbitrary call — potential callback vector
        }
        context = prevContext; // @audit-ok TAG-015: context restored after call — reentrancy guard also present

        if (success) {
            successfulMessages[messageId] = true;
        } else {
            failedMessages[messageId] = true; // @audit-info TAG-016: failed messages become retryable by anyone via else branch above
        }
    }

    function getSender() external view returns (address) {
        return context.l2Sender;
    }
}
