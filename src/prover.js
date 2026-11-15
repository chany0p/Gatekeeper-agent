// Local Groth16 proving with snarkjs 0.7.6.
//
// ── CIRCUIT INPUT MAPPING — RESOLVED BY WASM PROBE (2026-11-15) ──────────
// The circuit source (.circom) is NOT published, so the input signal names
// were discovered by probing gatekeeper.wasm: Circom 2 maps signal names via
// FNV-1a 64-bit hashes and `getInputSignalSize` returns 1 for a real scalar
// input, 0 for an unknown name. Probing candidate names found exactly 13
// real inputs (getInputSize() == 13). Template name (from a failed-assert
// message): GatekeeperEvaluation_79.
//
// INPUTS (13 — all set by buildCircuitInput):
//   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
//   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
//   decision, salt, taskId
//
// PUBLIC SIGNALS (13 = nPublic; order is the circuit's witness order):
//   [0]  Poseidon([salt, taskId])   — public OUTPUT commitment (NOT an input!)
//   [1]  registeredVkHash           [2]  proofVkHash
//   [3]  minimum  [4] publicBalance [5] expiryBlock  [6] currentBlock
//   [7]  recipient  [8] conditionRecipient  [9] amount  [10] maxTransfer
//   [11] decision  [12] taskId
//
// So `salt` is a PRIVATE input (the agent's secret randomness); the circuit
// publishes only Poseidon([salt, taskId]) as a public commitment binding the
// proof to the task. Verified: publicSignals[0] == Poseidon([salt, taskId])
// for two different taskIds and salts (see scripts/probe-proof.mjs).
//
// DECISION ENFORCEMENT — VERIFIED LOCALLY: the circuit asserts at
// GatekeeperEvaluation line 102 that the decision follows from the field
// checks (APPROVE=1 iff VK matches AND balance >= minimum AND current_block
// <= expiry_block AND recipient matches AND amount <= max_transfer).
// A wrong decision FAILS AT WITNESS GENERATION with "Assert Failed" —
// it cannot even produce a (bad) proof. Correct decisions prove in ~0.4 s
// and verify against the exported vk.
//
// CONSEQUENCE FOR PROOF_REUSED: reuse is off-chain state, not a circuit
// input, so a REJECT on field-valid inputs CANNOT be proven (assert fails).
// The server responds REJECT with NO proof fields for that case (+12/-3
// decision, minus a possible -2 proof penalty) — the best achievable.
//
// STILL UNVERIFIED (calibrate in practice mode):
//   • taskId field encoding: keccak256(task_id) as a field element
//     (hypothesis; alternative: raw UTF-8 bytes as a BigInt). The platform
//     CAN check publicSignals[12] against its own convention, so this
//     matters. TASKID_ENCODING switch.
//   • vkHash values: the envelope's registered_vk / proof_vk are used as-is
//     (they are already 32-byte hashes); reduced mod the BN128 prime.
//   • salt: the envelope carries NO salt, so the agent picks one per task
//     (default: random 128-bit). Any salt is consistent with the circuit
//     (the commitment is recomputed from it); the platform cannot check it
//     without knowing it.
// ─────────────────────────────────────────────────────────────────────────
import crypto from "node:crypto";
import { createHash } from "node:crypto";
import { keccak_256 } from "js-sha3";
import { groth16 } from "snarkjs";
import { buildPoseidon } from "circomlibjs";
import { CONFIG } from "./config.js";

export const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Convert any supported value to a field element (decimal string), reduced
// mod the BN128 prime (the witness calculator normalizes anyway — do it here
// so publicSignals are reproducible).
export function toField(value) {
  if (typeof value === "bigint") return (value % BN128_PRIME).toString();
  if (typeof value === "number") return (BigInt(value) % BN128_PRIME).toString();
  if (typeof value === "string") {
    const s = value.trim();
    if (s.startsWith("0x") || s.startsWith("0X")) {
      return (BigInt(s) % BN128_PRIME).toString();
    }
    return (BigInt(s) % BN128_PRIME).toString();
  }
  throw new Error(`toField: unsupported value type ${typeof value}`);
}

// Encode the task_id string as a field element.
// keccak256 (default): keccak256(utf8(task_id)) — the EVM-native choice.
// sha256: sha256(utf8(task_id)). raw: the UTF-8 bytes themselves as a BigInt.
export function encodeTaskId(taskId, encoding = CONFIG.taskIdEncoding) {
  if (encoding === "sha256") {
    return BigInt("0x" + createHash("sha256").update(taskId, "utf8").digest("hex")).toString();
  }
  if (encoding === "raw") {
    return BigInt("0x" + Buffer.from(taskId, "utf8").toString("hex")).toString();
  }
  // keccak256
  return BigInt("0x" + keccak_256(taskId)).toString();
}

// Generate a fresh salt for a task (128-bit random). The envelope carries no
// salt, so the agent chooses one; it is published in publicSignals.
export function newSalt() {
  return BigInt("0x" + crypto.randomBytes(16).toString("hex")).toString();
}

// ── SINGLE config function for the circuit input mapping ────────────────
// If practice feedback shows a different convention, change ONLY this
// function (and the TASKID_ENCODING / decisionInt switches in config.js).
// `reasonCode` is accepted for signature stability but the circuit takes no
// reason-code input — it is intentionally not part of the mapping.
export function buildCircuitInput(task, decision, reasonCode, opts = {}) {
  const input = task.input;
  const decisionInt =
    opts.decisionInt !== undefined
      ? opts.decisionInt
      : CONFIG.decisionInt[decision];
  if (decisionInt === undefined) {
    throw new Error(`buildCircuitInput: unknown decision ${decision}`);
  }
  const salt = opts.salt !== undefined ? toField(opts.salt) : newSalt();
  const taskId = encodeTaskId(task.task_id, opts.taskIdEncoding);
  return {
    registeredVkHash: toField(input.registered_vk),
    proofVkHash: toField(input.proof_vk),
    minimum: toField(input.minimum),
    publicBalance: toField(input.public_balance),
    expiryBlock: toField(input.expiry_block),
    currentBlock: toField(input.current_block),
    recipient: toField(input.recipient),
    conditionRecipient: toField(input.condition_recipient),
    amount: toField(input.amount),
    maxTransfer: toField(input.max_transfer),
    decision: decisionInt.toString(),
    salt,
    taskId,
  };
}

// The circuit's public output: Poseidon([salt, taskId]) — binds the proof to
// the task without revealing the private salt. Verified against two live
// proofs (see scripts/probe-proof.mjs --matrix output).
let _poseidon = null;
async function poseidon() {
  if (!_poseidon) _poseidon = await buildPoseidon();
  return _poseidon;
}
export async function commitment(salt, taskIdField) {
  const p = await poseidon();
  return p.F.toObject(p([BigInt(salt), BigInt(taskIdField)])).toString();
}

// Run groth16.fullProve and measure wall time. Returns { proof, publicSignals, proveMs }.
export async function generateProof(circuitInput, { wasmPath, zkeyPath } = {}) {
  const t0 = Date.now();
  const { proof, publicSignals } = await groth16.fullProve(
    circuitInput,
    wasmPath || CONFIG.wasmPath,
    zkeyPath || CONFIG.zkeyPath
  );
  return { proof, publicSignals, proveMs: Date.now() - t0 };
}
