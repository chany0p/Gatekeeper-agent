// Standalone proof probe — for practice-mode iteration on the circuit mapping.
// Given a sample task JSON (or a fixture name), generates a Groth16 proof +
// publicSignals and verifies the proof locally against the exported vk.
//
// Usage:
//   node scripts/probe-proof.mjs valid [--decision 1] [--taskid-enc keccak256|sha256|raw] [--salt 0]
//   node scripts/probe-proof.mjs --matrix            # 8-case decision-enforcement matrix
//   node scripts/probe-proof.mjs path/to/task.json [--decision 1]
//
// The matrix checks that the circuit ENFORCES the decision: a correct decision
// must verify, a wrong decision must NOT verify. If both verify, the circuit
// does not constrain the decision (proof still counts, decision checked by the
// platform). If neither verifies, the input encoding is wrong — try other
// --taskid-enc values / --salt values.
//
// NOTE: the mapping it tests is the one in src/prover.js buildCircuitInput
// (signal names discovered by probing gatekeeper.wasm; decision int,
// taskId encoding and salt remain UNVERIFIED until practice feedback).
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { groth16 } from "snarkjs";
import { buildCircuitInput, generateProof, encodeTaskId, commitment } from "../src/prover.js";
import { CONFIG } from "../src/config.js";
import { makeEnvelope, FIXTURES } from "../test/fixtures.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VK = JSON.parse(await readFile(path.join(ROOT, "artifacts", "gatekeeper-vk.json"), "utf8"));

function parseArgs(argv) {
  const args = { positionals: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--decision") args.decision = parseInt(argv[++i], 10);
    else if (a === "--taskid-enc") args.taskIdEncoding = argv[++i];
    else if (a === "--salt") args.salt = argv[++i];
    else if (a === "--matrix") args.matrix = true;
    else args.positionals.push(a);
  }
  return args;
}

async function runCase(name, env, decisionInt, opts) {
  const decision = decisionInt === 1 ? "APPROVE" : "REJECT";
  const circuitInput = buildCircuitInput(env, decision, "PROBE", {
    decisionInt,
    salt: opts.salt,
    taskIdEncoding: opts.taskIdEncoding,
  });
  const t0 = Date.now();
  let proof, publicSignals, proveMs, proveError;
  try {
    ({ proof, publicSignals, proveMs } = await generateProof(circuitInput));
  } catch (e) {
    proveError = e.message.slice(0, 160);
  }
  const wallMs = Date.now() - t0;
  let verifies = null;
  let verifyError = null;
  let commitmentOk = null;
  if (proof) {
    try {
      verifies = await groth16.verify(VK, publicSignals, proof);
    } catch (e) {
      verifyError = e.message.slice(0, 160);
    }
    // publicSignals[0] must equal Poseidon([salt, taskId]) — the circuit's
    // public commitment output (salt itself is a PRIVATE input).
    const expected = await commitment(circuitInput.salt, circuitInput.taskId);
    commitmentOk = publicSignals[0] === expected;
  }
  return { name, decision, decisionInt, proveMs, wallMs, proveError, verifies, verifyError, commitmentOk, publicSignals };
}

function printCase(r) {
  const status = r.proveError
    ? `PROVE-FAIL (assert): ${r.proveError}`
    : r.verifies === true
      ? `VERIFY OK${r.commitmentOk ? " + commitment OK" : " + commitment MISMATCH"}`
      : r.verifies === false
        ? "VERIFY FAIL"
        : `VERIFY-ERR: ${r.verifyError}`;
  console.log(
    `${r.name.padEnd(20)} decision=${r.decision}(${r.decisionInt})  prove=${r.proveMs ?? "-"}ms  -> ${status}`
  );
  if (r.publicSignals) console.log(`  publicSignals: [${r.publicSignals.join(", ")}]`);
}

const args = parseArgs(process.argv.slice(2));
const opts = { salt: args.salt, taskIdEncoding: args.taskIdEncoding || CONFIG.taskIdEncoding };
console.log(`taskIdEncoding=${opts.taskIdEncoding} salt=${opts.salt ?? "(random)"}`);

if (args.matrix) {
  // Correct decision must verify; a WRONG decision must fail — the circuit
  // enforces the decision with an assert at witness generation, so a wrong
  // decision fails at PROVE time (not at verify time). Both count as "the
  // circuit rejected the wrong decision".
  const cases = [
    ["valid", 1, true],
    ["valid", 0, false],
    ["vk_substitution", 0, true],
    ["vk_substitution", 1, false],
    ["threshold_mismatch", 0, true],
    ["recipient_mismatch", 0, true],
    ["amount_overflow", 0, true],
    ["expired_condition", 0, true],
  ];
  let pass = 0;
  for (const [name, dec, expectVerify] of cases) {
    const env = makeEnvelope(name, { taskId: `gk_probe_${name}_001` });
    const r = await runCase(name, env, dec, opts);
    printCase(r);
    const ok = expectVerify
      ? r.verifies === true && r.commitmentOk === true
      : r.verifies === false || r.proveError !== undefined;
    if (ok) pass++;
    else console.log(`  ** MISMATCH: expected verify=${expectVerify}, got verifies=${r.verifies} proveError=${r.proveError ?? "none"}`);
  }
  console.log(`\nmatrix: ${pass}/${cases.length} as expected`);
  process.exit(pass === cases.length ? 0 : 1);
}

let env;
let label;
if (args.positionals[0]) {
  const p = args.positionals[0];
  if (FIXTURES[p]) {
    env = makeEnvelope(p, { taskId: `gk_probe_${p}_001` });
    label = p;
  } else {
    env = JSON.parse(await readFile(p, "utf8"));
    label = p;
  }
} else {
  env = makeEnvelope("valid", { taskId: "gk_probe_valid_001" });
  label = "valid";
}
const decisionInt = args.decision !== undefined ? args.decision : FIXTURES[label]?.expected.decision === "APPROVE" ? 1 : 0;
const r = await runCase(label, env, decisionInt, opts);
printCase(r);
console.log(`\ncircuitInput taskId field (encoding ${opts.taskIdEncoding}): ${encodeTaskId(env.task_id, opts.taskIdEncoding)}`);
