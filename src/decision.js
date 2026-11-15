// Deterministic decision logic — plan §3. Pure comparisons, no LLM anywhere.
// All numeric fields are compared as BigInt (they arrive as decimal strings);
// addresses are compared case-insensitively (lowercased both sides).

export const REASON_CODES = {
  VALID_CONDITION: 0,
  VK_SUBSTITUTION: 1,
  THRESHOLD_MISMATCH: 2,
  PROOF_REUSED: 3,
  EXPIRED_CONDITION: 4,
  RECIPIENT_MISMATCH: 5,
  AMOUNT_OVERFLOW: 6,
};

export const DECISIONS = { APPROVE: "APPROVE", REJECT: "REJECT" };

// Precedence (PROPOSED — calibrate in practice mode):
// VK_SUBSTITUTION > RECIPIENT_MISMATCH > THRESHOLD_MISMATCH > AMOUNT_OVERFLOW
// > EXPIRED_CONDITION > PROOF_REUSED > VALID_CONDITION.
// Rationale: identity binding first, then payment terms, then time, then reuse.
export function decide(input, { proofTxSeen }) {
  const eqAddr = (a, b) =>
    typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
  const bi = (v) => BigInt(v);

  if (!eqAddr(input.proof_vk, input.registered_vk)) {
    return { decision: DECISIONS.REJECT, reason_code: "VK_SUBSTITUTION" };
  }
  if (!eqAddr(input.recipient, input.condition_recipient)) {
    return { decision: DECISIONS.REJECT, reason_code: "RECIPIENT_MISMATCH" };
  }
  if (bi(input.public_balance) < bi(input.minimum)) {
    return { decision: DECISIONS.REJECT, reason_code: "THRESHOLD_MISMATCH" };
  }
  if (bi(input.amount) > bi(input.max_transfer)) {
    return { decision: DECISIONS.REJECT, reason_code: "AMOUNT_OVERFLOW" };
  }
  if (bi(input.current_block) > bi(input.expiry_block)) {
    return { decision: DECISIONS.REJECT, reason_code: "EXPIRED_CONDITION" };
  }
  if (proofTxSeen) {
    return { decision: DECISIONS.REJECT, reason_code: "PROOF_REUSED" };
  }
  return { decision: DECISIONS.APPROVE, reason_code: "VALID_CONDITION" };
}

const REQUIRED_FIELDS = [
  "registered_vk",
  "proof_vk",
  "minimum",
  "public_balance",
  "expiry_block",
  "current_block",
  "recipient",
  "condition_recipient",
  "amount",
  "max_transfer",
  "proof_tx",
];

// Throws on missing/invalid fields; returns null when the envelope is well-formed.
export function validateInput(input) {
  if (!input || typeof input !== "object") return "input must be an object";
  for (const f of REQUIRED_FIELDS) {
    if (input[f] === undefined || input[f] === null || input[f] === "") {
      return `input.${f} is missing`;
    }
  }
  for (const f of ["minimum", "public_balance", "amount", "max_transfer"]) {
    try {
      BigInt(input[f]);
    } catch {
      return `input.${f} is not a valid integer string: ${String(input[f]).slice(0, 40)}`;
    }
  }
  for (const f of ["expiry_block", "current_block"]) {
    try {
      BigInt(input[f]);
    } catch {
      return `input.${f} is not a valid integer: ${String(input[f]).slice(0, 40)}`;
    }
  }
  return null;
}
