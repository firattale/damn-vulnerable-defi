// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IShardsNFTMarketplace} from "./IShardsNFTMarketplace.sol";
import {ShardsFeeVault} from "./ShardsFeeVault.sol";
import {DamnValuableToken} from "../DamnValuableToken.sol";
import {DamnValuableNFT} from "../DamnValuableNFT.sol";
import {FixedPointMathLib} from "solmate/utils/FixedPointMathLib.sol";

/**
 * @notice NFT marketplace where sellers offer NFTs, and buyers can collectively acquire pieces of them.
 *         Pieces of the NFT are represented by an integrated ERC1155 token.
 *         The marketplace charges sellers a 2% fee, stored in a secure on-chain vault.
 */ // @audit-info TAG-001: NatSpec says 2% fee but code computes 1% — documentation mismatch
contract ShardsNFTMarketplace is IShardsNFTMarketplace, IERC721Receiver, ERC1155 {
    using FixedPointMathLib for uint256;

    /// @notice how much time buyers must wait before they can cancel
    uint32 public constant TIME_BEFORE_CANCEL = 1 days;

    /// @notice for how long can buyers cancel
    uint32 public constant CANCEL_PERIOD_LENGTH = 2 days;

    DamnValuableNFT public immutable nft;
    DamnValuableToken public immutable paymentToken;
    ShardsFeeVault public immutable feeVault;
    address public immutable oracle;

    uint64 public offerCount;
    uint256 public feesInBalance;
    uint256 public rate; // @audit-info TAG-010: [knob] DVT per USDC rate — oracle-controlled, affects all pricing
    mapping(uint64 offerId => Offer) public offers;
    mapping(uint256 nftId => uint64 offerId) public nftToOffers;
    mapping(uint64 offerdId => Purchase[]) public purchases;

    constructor(
        DamnValuableNFT _nft,
        DamnValuableToken _paymentToken,
        address _feeVaultImplementation,
        address _oracle,
        uint256 _initialRate
    ) ERC1155("") {
        paymentToken = _paymentToken;
        nft = _nft;
        oracle = _oracle;
        rate = _initialRate;

        // Deploy minimal proxy for fee vault. Then initialize it and approve max
        feeVault = ShardsFeeVault(Clones.clone(_feeVaultImplementation));
        feeVault.initialize(msg.sender, _paymentToken);
        paymentToken.approve(address(feeVault), type(uint256).max);
    }

    /**
     * @notice Called by sellers to open offers of one NFT, specifying number of units (a.k.a. "shards") and the total price.
     *         Sellers cannot withdraw offers. They're open until completely filled.
     * @param nftId ID of the NFT to offer
     * @param totalShards how many shards for the NFT
     * @param price total price, expressed in USDC units
     */
    // @audit-info TAG-002: [knob] totalShards is user-controlled, no min/max validation — affects all price math
    function openOffer(uint256 nftId, uint256 totalShards, uint256 price) external returns (uint256) {
        // @audit-info TAG-003: no validation on totalShards — could be 0 (div-by-zero in fill) or extremely large
        if (price == 0) revert BadPrice();
        offerCount++; // offer IDs start at 1

        // create and store new offer
        offers[offerCount] = Offer({
            nftId: nftId,
            totalShards: totalShards,
            stock: totalShards,
            price: price,
            seller: msg.sender,
            isOpen: true
        });

        nftToOffers[nftId] = offerCount;

        emit NewOffer(offerCount, msg.sender, nftId, totalShards, price);

        _chargeFees(price);

        // pull NFT offered
        nft.safeTransferFrom(msg.sender, address(this), nftId, "");

        return offerCount;
    }

    /**
     * Caller can redeem and burn all shards to claim the associated NFT
     * @param nftId ID of the NFT to claim
     */
    function redeem(uint256 nftId) external {
        if (nft.ownerOf(nftId) != address(this)) revert UnknownNFT(nftId);
        uint64 offerId = nftToOffers[nftId];
        Offer memory offer = offers[offerId];
        if (offer.isOpen) revert StillOpen();

        delete offers[offerId];
        _burn(msg.sender, nftId, offer.totalShards);

        nft.safeTransferFrom(address(this), msg.sender, nftId, "");
    }

    // @audit-info TAG-009: anyone can call depositFees — moves DVT from marketplace to vault
    function depositFees(bool stake) external {
        feeVault.deposit(feesInBalance, stake);
        feesInBalance = 0;
    }

    /**
     * @notice Called by buyers to partially/fully fill offers, paying in DVT.
     *         These purchases can be cancelled.
     */
    function fill(uint64 offerId, uint256 want) external returns (uint256 purchaseIndex) {
        Offer storage offer = offers[offerId];
        if (want == 0) revert BadAmount();
        if (offer.price == 0) revert UnknownOffer();
        if (want > offer.stock) revert OutOfStock();
        if (!offer.isOpen) revert NotOpened(offerId);

        offer.stock -= want;
        purchaseIndex = purchases[offerId].length;
        // @audit-info TAG-013: [knob] rate snapshot per purchase — different purchases can have different rates
        uint256 _currentRate = rate;
        purchases[offerId].push(
            Purchase({
                shards: want,
                rate: _currentRate,
                buyer: msg.sender,
                timestamp: uint64(block.timestamp),
                cancelled: false
            })
        );
        // @audit-issue C-01: fill payment rounds DOWN to 0 for small want — free shards (critical-001)
        paymentToken.transferFrom(
            msg.sender, address(this), want.mulDivDown(_toDVT(offer.price, _currentRate), offer.totalShards)
        );
        if (offer.stock == 0) _closeOffer(offerId); // @audit-info TAG-014: [knob] buyer controls when offer closes by choosing exact want to deplete stock
    }

    /**
     * @notice To cancel open offers once the waiting period is over.
     */
    function cancel(uint64 offerId, uint256 purchaseIndex) external {
        Offer storage offer = offers[offerId];
        Purchase storage purchase = purchases[offerId][purchaseIndex];
        address buyer = purchase.buyer;

        if (msg.sender != buyer) revert NotAllowed();
        if (!offer.isOpen) revert NotOpened(offerId);
        if (purchase.cancelled) revert AlreadyCancelled();
        // @audit-issue C-01: broken time check allows immediate cancel in same block (critical-001)
        if (
            purchase.timestamp + CANCEL_PERIOD_LENGTH < block.timestamp
                || block.timestamp > purchase.timestamp + TIME_BEFORE_CANCEL
        ) revert BadTime();

        offer.stock += purchase.shards;
        assert(offer.stock <= offer.totalShards); // invariant
        purchase.cancelled = true;

        emit Cancelled(offerId, purchaseIndex);

        // @audit-issue C-01: cancel refund formula ignores price/totalShards — refunds ~1e13x more than paid (critical-001)
        paymentToken.transfer(buyer, purchase.shards.mulDivUp(purchase.rate, 1e6));
    }

    /**
     * @notice Allows an oracle account to set a new rate of DVT per USDC
     */
    function setRate(uint256 newRate) external {
        if (msg.sender != oracle) revert NotAllowed();
        if (newRate == 0 || rate == newRate) revert BadRate();
        rate = newRate;
    }

    /**
     * @notice Given a price in USDC, uses the oracle's rate to calculate the fees in DVT
     * @param price price in USDC units
     */
    function getFee(uint256 price, uint256 _rate) public pure returns (uint256) {
        uint256 fee = price.mulDivDown(1e6, 100e6); // @audit-info TAG-008: 1% fee, not 2% as NatSpec claims
        return _toDVT(fee, _rate);
    }

    function getOffer(uint64 offerId) external view returns (Offer memory) {
        return offers[offerId];
    }

    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function _chargeFees(uint256 price) private {
        uint256 feeAmount = getFee(price, rate);
        feesInBalance += feeAmount;
        emit Fee(feeAmount);
        paymentToken.transferFrom(msg.sender, address(this), feeAmount);
        assert(feesInBalance <= paymentToken.balanceOf(address(this))); // invariant
    }

    function _closeOffer(uint64 offerId) private {
        Offer memory offer = offers[offerId];
        Purchase[] memory _purchases = purchases[offerId];
        uint256 payment;

        for (uint256 i = 0; i < _purchases.length; i++) {
            Purchase memory purchase = _purchases[i];
            if (purchase.cancelled) continue;
            // @audit TAG-007: seller payment = shards * rate / 1e18 (mulWadUp) — THIRD different formula, divides by 1e18 not 1e6
            payment += purchase.shards.mulWadUp(purchase.rate);
            _mint({to: purchase.buyer, id: offer.nftId, value: purchase.shards, data: ""});
            assert(balanceOf(purchase.buyer, offer.nftId) <= offer.totalShards); // invariant
        }

        offers[offerId].isOpen = false;
        emit ClosedOffer(offerId);
        // @audit-info TAG-011: seller payment transfer — could exceed collected buyer payments due to TAG-007 math mismatch
        paymentToken.transfer(offer.seller, payment);
    }

    // @audit-info TAG-012: _toDVT divides by 1e6 — used in fill and getFee but NOT in cancel or _closeOffer
    function _toDVT(uint256 _value, uint256 _rate) private pure returns (uint256) {
        return _value.mulDivDown(_rate, 1e6);
    }
}
