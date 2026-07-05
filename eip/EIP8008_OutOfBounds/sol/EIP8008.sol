// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.35;

/**
 * @eip     EIP-8008
 * @title   Out-of-Bounds P256 Input Validation
 * @notice  Solidity layer for EIP-8008: defines the interface and a helper
 *          contract that classifies P256 verifier inputs as in-bounds or
 *          out-of-bounds before forwarding to the verifier. Rejects any public
 *          key coordinate that is zero or >= the curve prime field modulus p.
 * @layer   sol
 * @test    testOutOfBounds (test 2)
 *
 * Curve parameters (secp256r1 / P-256):
 *   p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
 *   n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
 */

// ---------------------------------------------------------------------------
// Interface
// ---------------------------------------------------------------------------

interface IP256Verifier {
    /**
     * @dev Raw fallback call: takes 160 bytes (hash || r || s || x || y) and
     *      returns bytes32(1) for a valid signature, bytes32(0) otherwise.
     */
    fallback() external returns (bytes32);
}

// ---------------------------------------------------------------------------
// EIP-8008 bounds-check wrapper
// ---------------------------------------------------------------------------

contract EIP8008_OutOfBounds {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice secp256r1 prime field modulus.
    uint256 public constant CURVE_P =
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;

    /// @notice secp256r1 scalar field order.
    uint256 public constant CURVE_N =
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error EIP8008__ZeroCoordinate();
    error EIP8008__CoordinateOutOfRange(string axis, uint256 value);
    error EIP8008__ScalarOutOfRange(string param, uint256 value);
    error EIP8008__InputLengthInvalid(uint256 length);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       BOUNDS CHECKS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Returns true iff both (x, y) are valid affine coordinates for
     *         the P-256 curve (non-zero and strictly less than p).
     */
    function isValidPublicKey(uint256 x, uint256 y) public pure returns (bool) {
        if (x == 0 || y == 0) return false;
        if (x >= CURVE_P || y >= CURVE_P) return false;
        return true;
    }

    /**
     * @notice Returns true iff r and s are valid scalar field elements
     *         (non-zero and strictly less than n).
     */
    function isValidScalars(uint256 r, uint256 s) public pure returns (bool) {
        if (r == 0 || s == 0) return false;
        if (r >= CURVE_N || s >= CURVE_N) return false;
        return true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     GUARDED VERIFY                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice Validate all inputs according to EIP-8008 rules, then forward
     *         to the underlying P256 verifier. Reverts with a descriptive
     *         error on any out-of-bounds input rather than returning false.
     * @param verifier  Address of the deployed P256Verifier contract.
     * @param hash      32-byte message digest.
     * @param r         Signature parameter r.
     * @param s         Signature parameter s.
     * @param x         Public key x coordinate.
     * @param y         Public key y coordinate.
     * @return valid    True iff the signature is valid.
     */
    function guardedVerify(
        address verifier,
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) external view returns (bool valid) {
        // --- EIP-8008-R1: public key coordinates must be non-zero ---
        if (x == 0 || y == 0) revert EIP8008__ZeroCoordinate();

        // --- EIP-8008-R2: public key coordinates must be < p ---
        if (x >= CURVE_P) revert EIP8008__CoordinateOutOfRange("x", x);
        if (y >= CURVE_P) revert EIP8008__CoordinateOutOfRange("y", y);

        // --- EIP-8008-R3: signature scalars must be in [1, n) ---
        if (r == 0 || r >= CURVE_N) revert EIP8008__ScalarOutOfRange("r", r);
        if (s == 0 || s >= CURVE_N) revert EIP8008__ScalarOutOfRange("s", s);

        // --- Forward validated input to the verifier ---
        bytes memory input = abi.encodePacked(hash, r, s, x, y);
        (bool success, bytes memory result) = verifier.staticcall(input);
        require(success, "EIP8008: verifier call failed");
        return abi.decode(result, (uint256)) == 1;
    }

    /**
     * @notice Silent variant: returns false for any out-of-bounds input
     *         rather than reverting. Mirrors the behaviour of the verifier
     *         itself (fast-fail without gas-intensive modexp).
     */
    function silentVerify(
        address verifier,
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) external view returns (bool valid) {
        if (!isValidPublicKey(x, y)) return false;
        if (!isValidScalars(r, s)) return false;

        bytes memory input = abi.encodePacked(hash, r, s, x, y);
        (bool success, bytes memory result) = verifier.staticcall(input);
        if (!success) return false;
        return abi.decode(result, (uint256)) == 1;
    }
}
