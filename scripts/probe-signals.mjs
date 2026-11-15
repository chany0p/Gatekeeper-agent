// Exploratory probe: which input signal names does gatekeeper.wasm accept?
// Circom 2 wasm maps signal names via FNV-1a 64-bit hash; getInputSignalSize
// returns -1 for unknown names. Run: node /tmp/probe-signals.mjs
import { readFile } from "node:fs/promises";
import wc from "../node_modules/circom_runtime/js/witness_calculator.js";

const wasm = await readFile(new URL("../artifacts/gatekeeper.wasm", import.meta.url));
const calc = await wc(wasm);
const inst = calc.instance ?? null;

// The circom_runtime builder returns a WitnessCalculator; expose internals via
// the instance through the calculator object. Fall back to re-instantiating raw.
let exports_;
if (calc.instance) {
  exports_ = calc.instance.exports;
} else {
  // builder returns object with methods; instance is internal — use calculateWitness errors instead
  exports_ = null;
}

const CANDIDATES = [
  "proofTxHash",
  "proofHash",
  "txHash",
  "proofRef",
  "proofReference",
  "reference",
  "refHash",
  "proofId",
  "reasoncode",
  "REASONCODE",
  "ReasonCode",
  "decisionReason",
  "reasonInt",
  "reasonId",
  "codeInt",
  "status",
  "statusCode",
  "checkCode",
  "failureReason",
  "rejectionReason",
  "rejectionCode",
  "trapCode",
  "expectedReason",
  "vkMatch",
  "vkMatches",
  "recipientMatch",
  "thresholdOk",
  "amountOk",
  "balanceOk",
  "notExpired",
  "notReused",
  "isExpired",
  "isReused",
  "checksPass",
  "allPassed",
  "allChecksPass",
  "nonce",
  "salt",
  "timestamp",
  "issuedAt",
  "deadlineAt",
  "taskId",
  "taskHash",
  "agentId",
  "chainId",
  "blockNumber",
  "expiry",
  "min",
  "max",
  "limit",
  "balance",
  "expectedDecision",
  "validDecision",
  "proofValid",
  "verified",
  "finalized",
  "conditionHash",
  "inputHash",
  "statementHash",
  "isFinalized",
  "proofVerified",
  "vkEqual",
  "recipientEqual",
  "amountValid",
  "thresholdMet",
  "blockValid",
  "proofReuse",
  "reuseCheck",
  "decisionCode",
  "gateDecision",
  "approvedAmount",
  "conditionMet",
  "conditionPassed",
  "passFail",
  "checkFlags",
  "flags",
];

function fnvHash(str) {
  const uint64_max = BigInt(2) ** BigInt(64);
  let hash = BigInt("0xCBF29CE484222325");
  for (let i = 0; i < str.length; i++) {
    hash ^= BigInt(str.charCodeAt(i));
    hash *= BigInt(0x100000001B3);
    hash %= uint64_max;
  }
  let shash = hash.toString(16);
  return "0".repeat(16 - shash.length) + shash;
}

if (!exports_) {
  console.log("NO direct wasm exports access; printing calculator props:", Object.keys(calc));
  process.exit(1);
}

console.log("version:", exports_.getVersion ? exports_.getVersion() : "?");
console.log("getInputSize():", exports_.getInputSize());
console.log("getWitnessSize():", exports_.getWitnessSize());
console.log("getFieldNumLen32():", exports_.getFieldNumLen32());

const found = [];
for (const name of CANDIDATES) {
  const h = fnvHash(name);
  const hMSB = parseInt(h.slice(0, 8), 16);
  const hLSB = parseInt(h.slice(8, 16), 16);
  let size = -999;
  try { size = exports_.getInputSignalSize(hMSB, hLSB); } catch (e) { size = `ERR ${e.message}`; }
  if (typeof size === "number" && size >= 0) {
    found.push([name, size]);
    console.log(`FOUND  ${name}  size=${size}`);
  }
}
console.log(`\n${found.length} candidate names accepted out of ${CANDIDATES.length}`);
