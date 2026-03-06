// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {FixedPointMathLib} from "solmate/utils/FixedPointMathLib.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {IStableSwap} from "./IStableSwap.sol";
import {CurvyPuppetOracle} from "./CurvyPuppetOracle.sol";
import {console} from "forge-std/console.sol";

// @audit-info TAG-001: no Ownable, no Pausable — no admin controls or emergency stop
contract CurvyPuppetLending is ReentrancyGuard {
    using FixedPointMathLib for uint256;

    address public immutable borrowAsset;
    address public immutable collateralAsset;
    IStableSwap public immutable curvePool;
    IPermit2 public immutable permit2;
    CurvyPuppetOracle public immutable oracle;

    struct Position {
        uint256 collateralAmount;
        uint256 borrowAmount;
    }

    mapping(address who => Position) public positions;

    error InvalidAmount();
    error NotEnoughCollateral();
    error HealthyPosition(uint256 borrowValue, uint256 collateralValue);
    error UnhealthyPosition();

    constructor(address _collateralAsset, IStableSwap _curvePool, IPermit2 _permit2, CurvyPuppetOracle _oracle) {
        borrowAsset = _curvePool.lp_token();
        collateralAsset = _collateralAsset;
        curvePool = _curvePool;
        permit2 = _permit2;
        oracle = _oracle;
    }

    // @audit-info TAG-002: [knob] no minimum deposit amount — attacker can deposit dust
    function deposit(uint256 amount) external nonReentrant {
        positions[msg.sender].collateralAmount += amount; // @audit-ok TAG-003: state updated before external call (CEI)
        _pullAssets(collateralAsset, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount();

        uint256 remainingCollateral = positions[msg.sender].collateralAmount - amount; // @audit-ok TAG-004: underflow reverts naturally in 0.8.25
        uint256 remainingCollateralValue = getCollateralValue(remainingCollateral);
        uint256 borrowValue = getBorrowValue(positions[msg.sender].borrowAmount);

        // @audit-info TAG-005: [knob] health check uses current oracle + virtual_price — manipulable at call time
        if (borrowValue * 175 > remainingCollateralValue * 100) revert UnhealthyPosition();

        positions[msg.sender].collateralAmount = remainingCollateral;
        IERC20(collateralAsset).transfer(msg.sender, amount); // @audit-info TAG-006: uses transfer not safeTransfer — DVT is known token so OK
    }

    // @audit TAG-007: MISSING nonReentrant modifier — all other state-changing functions have it
    function borrow(uint256 amount) external {
        // Get current collateral and borrow values
        uint256 collateralValue = getCollateralValue(positions[msg.sender].collateralAmount);
        uint256 currentBorrowValue = getBorrowValue(positions[msg.sender].borrowAmount);

        uint256 maxBorrowValue = collateralValue * 100 / 175; // @audit-info TAG-008: [knob] division truncation favors borrower slightly
        uint256 availableBorrowValue = maxBorrowValue - currentBorrowValue;

        if (amount == type(uint256).max) {
            // @audit-info TAG-009: [knob] max borrow uses divWadDown — attacker can borrow max in one call
            amount = availableBorrowValue.divWadDown(_getLPTokenPrice());
        }

        if (amount == 0) revert InvalidAmount();

        // Now do solvency check
        uint256 borrowAmountValue = getBorrowValue(amount);
        if (currentBorrowValue + borrowAmountValue > maxBorrowValue) revert NotEnoughCollateral();

        // Update caller's position and transfer borrowed assets
        positions[msg.sender].borrowAmount += amount;
        IERC20(borrowAsset).transfer(msg.sender, amount); // @audit-info TAG-010: LP token transfer — is LP token ERC20 with callbacks?
    }

    function redeem(uint256 amount) external nonReentrant {
        if (amount == 0) revert InvalidAmount();
        positions[msg.sender].borrowAmount -= amount;
        _pullAssets(borrowAsset, amount);

        // @audit-info TAG-011: auto-returns ALL collateral when borrow fully repaid — intended behavior per README
        if (positions[msg.sender].borrowAmount == 0) {
            uint256 returnAmount = positions[msg.sender].collateralAmount;
            positions[msg.sender].collateralAmount = 0;
            IERC20(collateralAsset).transfer(msg.sender, returnAmount);
        }
    }

    // @audit TAG-012: liquidation uses same price sources as borrow — virtual_price manipulation enables forced liquidation
    function liquidate(address target) external nonReentrant {
        uint256 borrowAmount = positions[target].borrowAmount;
        uint256 collateralAmount = positions[target].collateralAmount;

        // @audit TAG-013: [knob] health check reads virtual_price at call time — manipulable via Curve pool state
        uint256 collateralValue = getCollateralValue(collateralAmount) * 100;
        uint256 borrowValue = getBorrowValue(borrowAmount) * 175;
        if (collateralValue >= borrowValue) revert HealthyPosition(borrowValue, collateralValue);

        delete positions[target]; // @audit-info TAG-014: full position deletion — all collateral seized regardless of debt ratio

        _pullAssets(borrowAsset, borrowAmount);
        IERC20(collateralAsset).transfer(msg.sender, collateralAmount); // @audit-info TAG-015: collateral goes to liquidator, not back to user
    }

    // @audit-info TAG-016: mulWadUp for borrow, mulWadDown for collateral — rounding favors protocol (correct)
    function getBorrowValue(uint256 amount) public view returns (uint256) {
        if (amount == 0) return 0;
        return amount.mulWadUp(_getLPTokenPrice());
    }

    function getCollateralValue(uint256 amount) public view returns (uint256) {
        if (amount == 0) return 0;
        return amount.mulWadDown(oracle.getPrice(collateralAsset).value);
    }

    function getBorrowAmount(address who) external view returns (uint256) {
        return positions[who].borrowAmount;
    }

    function getCollateralAmount(address who) external view returns (uint256) {
        return positions[who].collateralAmount;
    }

    function _pullAssets(address asset, uint256 amount) private {
        permit2.transferFrom({from: msg.sender, to: address(this), amount: SafeCast.toUint160(amount), token: asset});
    }

    // @audit-issue CRITICAL-001: LP price = ETH_price * get_virtual_price() — virtual_price manipulable via Curve read-only reentrancy
    // @audit TAG-018: [knob] Curve stETH/ETH pool get_virtual_price() vulnerable to read-only reentrancy during remove_liquidity
    // @audit-info TAG-019: coins(0) = ETH — oracle returns ETH price. Assumes virtual_price is denominated in ETH terms
    function _getLPTokenPrice() private view returns (uint256) {
        return oracle.getPrice(curvePool.coins(0)).value.mulWadDown(curvePool.get_virtual_price());
    }
}
