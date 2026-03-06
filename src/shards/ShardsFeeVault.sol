// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Initializable} from "solady/utils/Initializable.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {DamnValuableStaking, DamnValuableToken} from "../DamnValuableStaking.sol";

/**
 * @notice  Permissioned vault to deposit fees of the NFT marketpkace.
 *          If a staking contract is set by the owner, the deposited tokens are staked.
 */
contract ShardsFeeVault is Initializable, Ownable {
    DamnValuableToken public token;
    DamnValuableStaking public staking;

    constructor() {
        _initializeOwner(address(0xdeadbeef));
        _disableInitializers();
    }

    function initialize(address _owner, DamnValuableToken _token) external initializer {
        _initializeOwner(_owner);
        token = _token;
    }

    // @audit-ok TAG-015: deposit is permissionless but requires transferFrom approval — marketplace has max approval
    function deposit(uint256 amount, bool stake) external {
        token.transferFrom(msg.sender, address(this), amount);
        if (address(staking) != address(0) && stake) {
            staking.stake(amount);
        }
    }

    // @audit-ok TAG-016: onlyOwner protects withdrawal — owner is deployer, not player-controlled
    function withdraw(address receiver, bool unstake) external onlyOwner {
        uint256 unstakedAmount = token.balanceOf(address(this));
        uint256 rewards;
        uint256 stakedAmount;
        if (address(staking) != address(0) && unstake) {
            rewards = staking.claim();
            stakedAmount = staking.balanceOf(address(this));
            staking.withdraw(stakedAmount);
        }
        token.transfer(receiver, unstakedAmount + rewards + stakedAmount);
    }

    function enableStaking(DamnValuableStaking _staking) external onlyOwner {
        staking = _staking;
        require(staking.token() == token);
        token.approve(address(_staking), type(uint256).max); // @audit-info TAG-017: max approval to staking contract
    }
}
