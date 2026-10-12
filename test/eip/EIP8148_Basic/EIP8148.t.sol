// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.35;

/**
 * @custom:eip    EIP-8148
 * @title         Basic P256 Signature Verification
 * @notice        Foundry layer for EIP-8148: sanity-checks input/output handling of
 *                the P256 (secp256r1) verifier. Validates zero inputs, a valid
 *                Wycheproof vector, and an off-by-one invalid key.
 * @custom:layer  foundry
 * @custom:test   testBasic (test 1)
 */

import {Test, console} from "forge-std/Test.sol";
import {VyperDeployer} from "vyper-deployer/VyperDeployer.sol";

contract EIP8148_Basic is Test {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HELPER VARIABLES                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    VyperDeployer private vyperDeployer = new VyperDeployer();
    address private p256Verifier;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      HELPER FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function evaluate(bytes32 hash, uint256 r, uint256 s, uint256 x, uint256 y)
        private
        view
        returns (bool valid, uint256 gasUsed)
    {
        bytes memory input = abi.encodePacked(hash, r, s, x, y);
        uint256 gasBefore = gasleft();
        (bool success, bytes memory res) = p256Verifier.staticcall(input);
        gasUsed = gasBefore - gasleft();
        assertEq(success, true, "EIP8148: call failed");
        assertEq(res.length, 32, "EIP8148: invalid result length");
        uint256 result = abi.decode(res, (uint256));
        assertTrue(result == 1 || result == 0, "EIP8148: result must be 0 or 1");
        return (result == 1, gasUsed);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                            SETUP                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function setUp() public {
        p256Verifier = vyperDeployer.deployContract("contracts/", "P256Verifier");
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  EIP-8148 TEST CASES                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * @notice EIP-8148-T1: Zero inputs must return false.
     */
    function testEIP8148_ZeroInputs() public view {
        bytes32 hash = bytes32(0);
        (uint256 r, uint256 s, uint256 x, uint256 y) = (0, 0, 0, 0);
        (bool res, uint256 gasUsed) = evaluate(hash, r, s, x, y);
        console.log("[EIP-8148] Zero inputs gasUsed:", gasUsed);
        console.log("[EIP-8148] Bytecode size:", p256Verifier.code.length);
        assertEq(res, false, "EIP8148-T1: zero inputs must return false");
    }

    /**
     * @notice EIP-8148-T2: First Wycheproof vector must return true.
     */
    function testEIP8148_ValidSignature() public view {
        bytes32 hash = 0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023;
        uint256 r = 19738613187745101558623338726804762177711919211234071563652772152683725073944;
        uint256 s = 34753961278895633991577816754222591531863837041401341770838584739693604822390;
        uint256 x = 18614955573315897657680976650685450080931919913269223958732452353593824192568;
        uint256 y = 90223116347859880166570198725387569567414254547569925327988539833150573990206;
        (bool res, uint256 gasUsed) = evaluate(hash, r, s, x, y);
        console.log("[EIP-8148] Valid sig gasUsed:", gasUsed);
        assertEq(res, true, "EIP8148-T2: valid signature must return true");
    }

    /**
     * @notice EIP-8148-T3: Off-by-one public key must return false.
     */
    function testEIP8148_InvalidSignature() public view {
        bytes32 hash = 0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023;
        uint256 r = 19738613187745101558623338726804762177711919211234071563652772152683725073944;
        uint256 s = 34753961278895633991577816754222591531863837041401341770838584739693604822390;
        uint256 x = 18614955573315897657680976650685450080931919913269223958732452353593824192568;
        uint256 y = 90223116347859880166570198725387569567414254547569925327988539833150573990206;
        (bool res, uint256 gasUsed) = evaluate(hash, r, s, x + 1, y);
        console.log("[EIP-8148] Invalid sig gasUsed:", gasUsed);
        assertEq(res, false, "EIP8148-T3: off-by-one key must return false");
    }
}
