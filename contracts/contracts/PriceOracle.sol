// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./TLSNotaryVerifier.sol";

/**
 * @title PriceOracle
 * @notice On-chain price oracle that verifies and stores prices from TLSNotary proofs
 * @dev Uses TLSNotaryVerifier to cryptographically verify prices from external APIs
 */
contract PriceOracle {

    // ============================================
    // STATE VARIABLES
    // ============================================

    /// @notice The TLSNotary verifier contract
    TLSNotaryVerifier public immutable verifier;

    /// @notice Trusted notary public key
    bytes public trustedNotaryPubkey;

    /// @notice Owner of the contract (can update trusted notary)
    address public owner;

    // ============================================
    // STRUCTS
    // ============================================

    /// @notice Stores verified price data
    struct PriceData {
        string price;              // Price as a string (e.g., "109102.01000000")
        uint256 timestamp;         // When the price was submitted on-chain
        uint256 blockNumber;       // Block number when submitted
        address submitter;         // Address that submitted the proof
        bytes32 proofHash;         // Hash of the proof to prevent duplicates
        bool exists;               // Whether this price exists
    }

    /// @notice Parameters for proof verification
    struct ProofParams {
        bytes plaintext;
        bytes16 blinder;
        bytes32 committedHash;
        bytes32 fieldHash;           // Pre-computed field hash from oracle
        bytes32[] merkleProofHashes;  // Computed off-chain [H23, H01]
        uint256 leafIndex;
        uint256 leafCount;
        bytes headerSerialized;
        bytes signature;
        bytes notaryPubkey;
        uint256 priceStart;
        uint256 priceEnd;
    }

    // ============================================
    // STORAGE
    // ============================================

    /// @notice Latest verified price for each symbol
    mapping(string => PriceData) public latestPrices;

    /// @notice Historical prices: symbol => timestamp => PriceData
    mapping(string => mapping(uint256 => PriceData)) public historicalPrices;

    /// @notice Tracks if a proof has been used (prevents replay attacks)
    mapping(bytes32 => bool) public usedProofs;

    // ============================================
    // EVENTS
    // ============================================

    event PriceUpdated(
        string indexed symbol,
        string price,
        uint256 timestamp,
        uint256 blockNumber,
        address indexed submitter,
        bytes32 indexed proofHash
    );

    event TrustedNotaryUpdated(
        bytes oldPubkey,
        bytes newPubkey,
        address indexed updatedBy
    );

    event OwnershipTransferred(
        address indexed previousOwner,
        address indexed newOwner
    );

    // ============================================
    // ERRORS
    // ============================================

    error ProofAlreadyUsed();
    error UntrustedNotary();
    error OnlyOwner();

    // ============================================
    // MODIFIERS
    // ============================================

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    // ============================================
    // CONSTRUCTOR
    // ============================================

    /**
     * @notice Initializes the PriceOracle with a verifier and trusted notary
     * @param _verifier Address of the TLSNotaryVerifier contract
     * @param _trustedNotaryPubkey The trusted notary's public key (33 bytes compressed)
     */
    constructor(address _verifier, bytes memory _trustedNotaryPubkey) {
        verifier = TLSNotaryVerifier(_verifier);
        trustedNotaryPubkey = _trustedNotaryPubkey;
        owner = msg.sender;
    }

    // ============================================
    // MAIN FUNCTIONS
    // ============================================

    /**
     * @notice Updates the price for a symbol by verifying a TLSNotary proof
     * @dev Performs full cryptographic verification before storing the price
     * @param symbol The asset symbol (e.g., "BTCUSDT")
     * @param params Struct containing all proof parameters
     * @return success True if the price was updated successfully
     */
    function updatePrice(
        string memory symbol,
        ProofParams memory params
    ) external returns (bool success) {
        // Verify the notary is trusted
        if (keccak256(params.notaryPubkey) != keccak256(trustedNotaryPubkey)) {
            revert UntrustedNotary();
        }

        // Create a unique proof hash to prevent replay attacks
        bytes32 proofHash = keccak256(
            abi.encodePacked(
                params.committedHash,
                params.headerSerialized,
                params.signature
            )
        );

        // Check if proof has been used before
        if (usedProofs[proofHash]) {
            revert ProofAlreadyUsed();
        }

        // Verify the TLSNotary proof and get price in one step
        string memory price = _verifyProofAndGetPrice(params);

        // Mark proof as used
        usedProofs[proofHash] = true;

        // Store and emit
        _storeAndEmit(symbol, price, proofHash);

        return true;
    }

    /**
     * @dev Helper to verify proof and extract price
     */
    function _verifyProofAndGetPrice(ProofParams memory params) private returns (string memory) {
        // Construct ProofData struct from ProofParams
        TLSNotaryVerifier.ProofData memory proofData = TLSNotaryVerifier.ProofData({
            plaintext: params.plaintext,
            blinder: params.blinder,
            committedHash: params.committedHash,
            fieldHash: params.fieldHash,
            merkleProofHashes: params.merkleProofHashes,
            leafIndex: params.leafIndex,
            leafCount: params.leafCount,
            headerSerialized: params.headerSerialized,
            signature: params.signature,
            notaryPubkey: params.notaryPubkey,
            priceStart: params.priceStart,
            priceEnd: params.priceEnd
        });

        (bool verified, string memory price) = verifier.verifyTLSNotaryProof(proofData);
        require(verified, "Proof verification failed");
        return price;
    }

    /**
     * @dev Helper to store and emit price data
     */
    function _storeAndEmit(
        string memory symbol,
        string memory price,
        bytes32 proofHash
    ) private {
        PriceData memory priceData = PriceData({
            price: price,
            timestamp: block.timestamp,
            blockNumber: block.number,
            submitter: msg.sender,
            proofHash: proofHash,
            exists: true
        });

        latestPrices[symbol] = priceData;
        historicalPrices[symbol][block.timestamp] = priceData;

        emit PriceUpdated(
            symbol,
            price,
            block.timestamp,
            block.number,
            msg.sender,
            proofHash
        );
    }

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Gets the latest verified price for a symbol
     * @param symbol The asset symbol
     * @return priceData The latest price data
     */
    function getLatestPrice(string memory symbol)
        external
        view
        returns (PriceData memory priceData)
    {
        return latestPrices[symbol];
    }

    /**
     * @notice Gets a historical price for a symbol at a specific timestamp
     * @param symbol The asset symbol
     * @param timestamp The timestamp to query
     * @return priceData The historical price data
     */
    function getHistoricalPrice(string memory symbol, uint256 timestamp)
        external
        view
        returns (PriceData memory priceData)
    {
        return historicalPrices[symbol][timestamp];
    }

    /**
     * @notice Checks if a price exists for a symbol
     * @param symbol The asset symbol
     * @return exists True if a price exists
     */
    function priceExists(string memory symbol) external view returns (bool exists) {
        return latestPrices[symbol].exists;
    }

    /**
     * @notice Checks if a proof has been used
     * @param proofHash The hash of the proof
     * @return used True if the proof has been used
     */
    function isProofUsed(bytes32 proofHash) external view returns (bool used) {
        return usedProofs[proofHash];
    }

    // ============================================
    // ADMIN FUNCTIONS
    // ============================================

    /**
     * @notice Updates the trusted notary public key
     * @param newNotaryPubkey The new notary public key
     */
    function updateTrustedNotary(bytes memory newNotaryPubkey) external onlyOwner {
        bytes memory oldPubkey = trustedNotaryPubkey;
        trustedNotaryPubkey = newNotaryPubkey;

        emit TrustedNotaryUpdated(oldPubkey, newNotaryPubkey, msg.sender);
    }

    /**
     * @notice Transfers ownership of the contract
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid new owner");
        address oldOwner = owner;
        owner = newOwner;

        emit OwnershipTransferred(oldOwner, newOwner);
    }
}
