/**
 * @eip     EIP-8131
 * @title   Wrong Input Length Validation
 * @notice  JavaScript layer for EIP-8131: verifies that the P256 verifier
 *          contract strictly rejects calldata that is not exactly 160 bytes.
 *          Uses ethers.js (v6) for ABI encoding and low-level calls.
 * @layer   js
 * @test    testWrongInputLength (test 3)
 *
 * Run with:  node EIP8131.js <RPC_URL> <VERIFIER_ADDRESS>
 * Example:   node EIP8131.js http://127.0.0.1:8545 0xDeAdBeEf...
 */

"use strict";

// ---------------------------------------------------------------------------
// Dependencies  (ethers v6 — installed via: npm install ethers)
// ---------------------------------------------------------------------------
const { ethers } = require("ethers");

// ---------------------------------------------------------------------------
// EIP-8131 constants
// ---------------------------------------------------------------------------
const EIP = "EIP-8131";
const EXPECTED_INPUT_LENGTH = 160; // 5 × 32 bytes: hash || r || s || x || y

// First valid Wycheproof vector (same as existing Foundry test suite).
const VECTOR = {
  hash: "0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
  r: "0x2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18",
  s: "0x4cd60b855d442f5a3c4c9aea64be4c3e44ab7ea3a80a78e4b99db8b65be5fd18",
  x: "0x29260a9b6f4aabaed228571e87474de48ccfc1d23c9e99dfaa9f16f85edd29e8",
  y: "0xc75a39fcd8a0fb2d27a9bc06e47e4e8e7c02ebf60c4b18d3d1c48f3c1c48f3c8",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Encode the 5 fields into raw 160-byte calldata (no function selector).
 * @param {string} hash  - 32-byte hex string
 * @param {string} r     - 32-byte hex string
 * @param {string} s     - 32-byte hex string
 * @param {string} x     - 32-byte hex string
 * @param {string} y     - 32-byte hex string
 * @returns {Uint8Array}
 */
function encodeInput(hash, r, s, x, y) {
  const fields = [hash, r, s, x, y].map((v) =>
    ethers.getBytes(ethers.zeroPadValue(v, 32))
  );
  const buf = new Uint8Array(160);
  fields.forEach((f, i) => buf.set(f, i * 32));
  return buf;
}

/**
 * Low-level staticcall to the verifier and return the decoded uint256.
 * Returns null if the call reverts.
 */
async function callVerifier(provider, verifierAddress, calldata) {
  try {
    const result = await provider.call({
      to: verifierAddress,
      data: ethers.hexlify(calldata),
    });
    if (!result || result === "0x") return null;
    return BigInt(result);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// EIP-8131 test cases
// ---------------------------------------------------------------------------

const tests = [
  {
    id: `${EIP}-T1`,
    name: "Exact 160-byte input returns 1 (valid signature)",
    async run(provider, verifier) {
      const input = encodeInput(
        VECTOR.hash,
        VECTOR.r,
        VECTOR.s,
        VECTOR.x,
        VECTOR.y
      );
      if (input.length !== EXPECTED_INPUT_LENGTH)
        throw new Error(`Encoding error: got ${input.length} bytes`);
      const result = await callVerifier(provider, verifier, input);
      if (result !== 1n)
        throw new Error(`Expected 1, got ${result}`);
    },
  },
  {
    id: `${EIP}-T2`,
    name: "161-byte input (trailing 0x00) returns 0 (invalid length)",
    async run(provider, verifier) {
      const base = encodeInput(
        VECTOR.hash,
        VECTOR.r,
        VECTOR.s,
        VECTOR.x,
        VECTOR.y
      );
      const input = new Uint8Array(161);
      input.set(base, 0);
      // trailing byte is 0x00 by default
      const result = await callVerifier(provider, verifier, input);
      if (result !== 0n)
        throw new Error(`Expected 0, got ${result}`);
    },
  },
  {
    id: `${EIP}-T3`,
    name: "159-byte input (truncated) returns 0 (invalid length)",
    async run(provider, verifier) {
      const base = encodeInput(
        VECTOR.hash,
        VECTOR.r,
        VECTOR.s,
        VECTOR.x,
        VECTOR.y
      );
      const input = base.slice(0, 159);
      const result = await callVerifier(provider, verifier, input);
      if (result !== 0n)
        throw new Error(`Expected 0, got ${result}`);
    },
  },
  {
    id: `${EIP}-T4`,
    name: "Empty calldata returns 0 (invalid length)",
    async run(provider, verifier) {
      const result = await callVerifier(provider, verifier, new Uint8Array(0));
      if (result !== 0n)
        throw new Error(`Expected 0, got ${result}`);
    },
  },
  {
    id: `${EIP}-T5`,
    name: "192-byte input (extra 32-byte word appended) returns 0 (invalid length)",
    async run(provider, verifier) {
      const base = encodeInput(
        VECTOR.hash,
        VECTOR.r,
        VECTOR.s,
        VECTOR.x,
        VECTOR.y
      );
      const input = new Uint8Array(192);
      input.set(base, 0);
      const result = await callVerifier(provider, verifier, input);
      if (result !== 0n)
        throw new Error(`Expected 0, got ${result}`);
    },
  },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

async function main() {
  const [, , rpcUrl, verifierAddress] = process.argv;

  if (!rpcUrl || !verifierAddress) {
    console.error(
      `Usage: node EIP8131.js <RPC_URL> <VERIFIER_ADDRESS>\n` +
        `Example: node EIP8131.js http://127.0.0.1:8545 0xAbCd...`
    );
    process.exit(1);
  }

  const provider = new ethers.JsonRpcProvider(rpcUrl);

  console.log(`\n[${EIP}] Wrong Input Length Validation`);
  console.log(`  verifier: ${verifierAddress}`);
  console.log(`  network:  ${(await provider.getNetwork()).name}\n`);

  let passed = 0;
  let failed = 0;

  for (const t of tests) {
    try {
      await t.run(provider, verifierAddress);
      console.log(`  ✅ ${t.id}: ${t.name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ ${t.id}: ${t.name}`);
      console.error(`     ${err.message}`);
      failed++;
    }
  }

  console.log(`\n[${EIP}] Results: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
