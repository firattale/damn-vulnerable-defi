// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {TrustfulOracle} from "./TrustfulOracle.sol";
import {DamnValuableNFT} from "../DamnValuableNFT.sol";
import "forge-std/console.sol";

contract Exchange is ReentrancyGuard {
    using Address for address payable;

    DamnValuableNFT public immutable token;
    TrustfulOracle public immutable oracle;

    error InvalidPayment();
    error SellerNotOwner(uint256 id);
    error TransferNotApproved();
    error NotEnoughFunds();

    event TokenBought(address indexed buyer, uint256 tokenId, uint256 price);
    event TokenSold(address indexed seller, uint256 tokenId, uint256 price);

    constructor(address _oracle) payable {
        token = new DamnValuableNFT();
        token.renounceOwnership();
        oracle = TrustfulOracle(_oracle);
    }

    function buyOne() external payable nonReentrant returns (uint256 id) {
        if (msg.value == 0) {
            revert InvalidPayment();
        }

        // @audit can we manipulate the price and buy an NFT? we have only 0.1 ether
        // @audit-info can we buy an NFT for 0.1 ether?
        // @audit-info current NFT price is 999 ether
        // Price should be in [wei / NFT]
        uint256 price = oracle.getMedianPrice(token.symbol());

        if (msg.value < price) {
            revert InvalidPayment();
        }

        id = token.safeMint(msg.sender);
        // @audit-ok why is this unchecked? can it overflow or underflow?
        // @audit-ok no, it can't overflow or underflow because msg.value is always bigger than price
        unchecked {
            payable(msg.sender).sendValue(msg.value - price);
        }

        emit TokenBought(msg.sender, id, price);
    }

    function sellOne(uint256 id) external nonReentrant {
        if (msg.sender != token.ownerOf(id)) {
            revert SellerNotOwner(id);
        }

        if (token.getApproved(id) != address(this)) {
            revert TransferNotApproved();
        }

        // Price should be in [wei / NFT]
        // @audit if we can buy somehow an NFT for 0.1 ether, we can sell it for 999 ether
        uint256 price = oracle.getMedianPrice(token.symbol());
        if (address(this).balance < price) {
            revert NotEnoughFunds();
        }

        token.transferFrom(msg.sender, address(this), id);
        token.burn(id);

        payable(msg.sender).sendValue(price);

        emit TokenSold(msg.sender, id, price);
    }

    receive() external payable {}
}
