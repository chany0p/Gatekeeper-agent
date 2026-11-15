// Test fixtures: sample envelope from gatekeeper-plan.md §1.1 + one per trap type.
// Timestamps are generated fresh on each call so fixtures never expire.
// All hex values are realistic full-length values (32-byte vk hashes, 20-byte
// addresses, 32-byte proof refs).
//
// Usage (ESM):
//   import { makeEnvelope, FIXTURES } from "../test/fixtures.mjs";
//   const env = makeEnvelope("valid"); // { type, task_id, mode, issued_at, deadline_at, input }

const VK_REGISTERED =
  "0x7d3a9c1e5f8b2a4d6c0e1f3a5b7d9e2c4a6b8d0f1e3a5c7b9d1e3f5a79a1b2";
const VK_OTHER =
  "0x13aa55c1e5f8b2a4d6c0e1f3a5b7d9e2c4a6b8d0f1e3a5c7b9d1e3f5a7bb2c3";
const ADDR_A = "0xDe42a7b3c1d5e6f8091a2b3c4d5e6f708192a01b";
const ADDR_B = "0xBEEF11aa22bb33cc44dd55ee66ff77889900aabbcc";
const PROOF_TX_FRESH =
  "0xa8c1d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a2b3c4d5e6f70a1";
const PROOF_TX_SEEN =
  "0x9999d2e3f405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a2b3c4d5e6f71b2";

function baseInput(overrides = {}) {
  return {
    registered_vk: VK_REGISTERED,
    proof_vk: VK_REGISTERED,
    minimum: "1000",
    public_balance: "1460",
    expiry_block: 8430000,
    current_block: 8420000,
    recipient: ADDR_A,
    condition_recipient: ADDR_A,
    amount: "500",
    max_transfer: "1000",
    proof_tx: PROOF_TX_FRESH,
    ...overrides,
  };
}

// Expected outcomes under the plan's decision logic (§3) with precedence
// VK_SUBSTITUTION > RECIPIENT_MISMATCH > THRESHOLD_MISMATCH > AMOUNT_OVERFLOW
// > EXPIRED_CONDITION > PROOF_REUSED > VALID_CONDITION.
export const FIXTURES = {
  // All checks pass.
  valid: {
    input: baseInput(),
    expected: { decision: "APPROVE", reason_code: "VALID_CONDITION" },
  },
  // proof_vk != registered_vk
  vk_substitution: {
    input: baseInput({ proof_vk: VK_OTHER }),
    expected: { decision: "REJECT", reason_code: "VK_SUBSTITUTION" },
  },
  // public_balance < minimum
  threshold_mismatch: {
    input: baseInput({ public_balance: "500" }),
    expected: { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" },
  },
  // proof_tx already seen (same tx as `valid`; harness must run `valid` first)
  proof_reused: {
    input: baseInput({ proof_tx: PROOF_TX_FRESH }),
    expected: { decision: "REJECT", reason_code: "PROOF_REUSED" },
  },
  // current_block > expiry_block
  expired_condition: {
    input: baseInput({ current_block: 8440000 }),
    expected: { decision: "REJECT", reason_code: "EXPIRED_CONDITION" },
  },
  // recipient != condition_recipient
  recipient_mismatch: {
    input: baseInput({ recipient: ADDR_B }),
    expected: { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" },
  },
  // amount > max_transfer
  amount_overflow: {
    input: baseInput({ amount: "1500" }),
    expected: { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" },
  },
  // Co-occurring traps: VK mismatch + recipient mismatch + threshold.
  // Precedence says VK_SUBSTITUTION wins.
  multi_trap: {
    input: baseInput({
      proof_vk: VK_OTHER,
      recipient: ADDR_B,
      public_balance: "100",
    }),
    expected: { decision: "REJECT", reason_code: "VK_SUBSTITUTION" },
  },
};

export const FIXTURE_NAMES = Object.keys(FIXTURES);

// Fresh envelope with a valid 55 s window (inside the 60 s hard deadline).
export function makeEnvelope(name, { taskId, deadlineSeconds = 55 } = {}) {
  const f = FIXTURES[name];
  if (!f) throw new Error(`unknown fixture: ${name}`);
  const now = new Date();
  const deadline = new Date(now.getTime() + deadlineSeconds * 1000);
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId ?? `gk_test_${name}_001`,
    mode: "competition",
    issued_at: now.toISOString(),
    deadline_at: deadline.toISOString(),
    input: structuredClone(f.input),
  };
}

export const PREFLIGHT = {
  type: "agent-games.preflight.v1",
  agent_id: "agt_test_001",
  issued_at: new Date().toISOString(),
  nonce: "test-nonce-001",
};
