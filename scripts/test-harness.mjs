// Local test harness — replays the sample envelope + one fixture per trap
// type against the running service with a dummy HMAC secret, in mock-Kurier
// mode (no network). Verifies decision + reason_code + proof generation +
// idempotency (same task_id twice = same response, no re-prove).
//
// Usage:  npm test        (or: node scripts/test-harness.mjs)
// Spawns the server itself (TEST mode, fresh temp STATE_DIR), runs the
// checks, prints PASS/FAIL per check, exits non-zero on any failure.
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { makeEnvelope, FIXTURES, PREFLIGHT } from "../test/fixtures.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PORT = 3101;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = "test-secret-dummy"; // the TEST-mode dummy (see src/config.js)

let pass = 0;
let fail = 0;
const failures = [];
function check(name, ok, extra = "") {
  if (ok) {
    pass++;
    console.log(`PASS  ${name}`);
  } else {
    fail++;
    failures.push(name);
    console.log(`FAIL  ${name} ${extra}`);
  }
}

function sign(rawBody) {
  return crypto.createHmac("sha256", SECRET).update(rawBody).digest("hex");
}
function verifySig(rawBody, sig) {
  if (!sig) return false;
  const a = Buffer.from(sig, "hex");
  const b = Buffer.from(sign(rawBody), "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function postJson(obj, { signature = true } = {}) {
  const raw = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (signature) headers["x-agent-games-signature"] = sign(raw);
  const t0 = Date.now();
  const res = await fetch(`${BASE}/agent`, { method: "POST", headers, body: raw });
  const text = await res.text();
  return { status: res.status, text, ms: Date.now() - t0, sig: res.headers.get("x-agent-games-signature") };
}

async function waitHealthz(server, tries = 50) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.status === 200) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

async function main() {
  const stateDir = mkdtempSync(path.join(tmpdir(), "gk-test-state-"));
  const server = spawn("node", ["src/server.js"], {
    cwd: ROOT,
    env: {
      ...process.env,
      AGENT_GAMES_TEST_MODE: "1",
      KURIER_MOCK: "1",
      PORT: String(PORT),
      STATE_DIR: stateDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let serverLog = "";
  server.stdout.on("data", (d) => { serverLog += d.toString(); });
  server.stderr.on("data", (d) => { serverLog += d.toString(); });

  try {
    check("server starts + /healthz 200", await waitHealthz(server), "(server did not come up)");

    // Preflight, correctly signed.
    {
      const r = await postJson({ ...PREFLIGHT, issued_at: new Date().toISOString() });
      const body = JSON.parse(r.text);
      check("preflight 200 {ok:true, protocolVersion:v1}", r.status === 200 && body.ok === true && body.protocolVersion === "v1", r.text.slice(0, 200));
      check("preflight response is HMAC-signed", verifySig(r.text, r.sig));
    }
    // Preflight with a bad signature -> 401 (also covers unsigned).
    {
      const raw = JSON.stringify(PREFLIGHT);
      const res = await fetch(`${BASE}/agent`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-agent-games-signature": "00".repeat(32) },
        body: raw,
      });
      check("bad signature -> 401", res.status === 401, `got ${res.status}`);
    }
    // Unknown type -> 400.
    {
      const r = await postJson({ type: "agent-games.nope.v1" });
      check("unknown type -> 400", r.status === 400, `got ${r.status}`);
    }

    // Trap fixtures, in order. `valid` runs first so its proof_tx is recorded
    // before `proof_reused` replays it. All fixtures share one proof_tx on
    // purpose: precedence must still yield each fixture's own reason code.
    const latencies = [];
    let validBody = null;
    for (const name of ["valid", "vk_substitution", "threshold_mismatch", "proof_reused", "expired_condition", "recipient_mismatch", "amount_overflow"]) {
      const env = makeEnvelope(name, { taskId: `gk_harness_${name}_001` });
      const r = await postJson(env);
      latencies.push(r.ms);
      let body;
      try { body = JSON.parse(r.text); } catch { body = null; }
      const exp = FIXTURES[name].expected;
      check(`${name}: status 200`, r.status === 200, `got ${r.status}: ${r.text.slice(0, 200)}`);
      if (body) {
        check(`${name}: decision=${exp.decision} reason=${exp.reason_code}`,
          body.decision === exp.decision && body.reason_code === exp.reason_code,
          `got ${body.decision}/${body.reason_code}`);
        check(`${name}: proof_tx echoes input`, body.proof_tx === env.input.proof_tx);
        check(`${name}: response is HMAC-signed`, verifySig(r.text, r.sig));
        if (name === "proof_reused") {
          // The circuit cannot prove a REJECT on field-valid inputs (reuse
          // is off-chain state): expect NO proof fields, decision only.
          check(`${name}: no proof fields (circuit cannot prove reuse REJECT)`,
            body.proof === undefined && body.public_signals === undefined,
            `got proof=${!!body.proof}`);
        } else {
          check(`${name}: proof + public_signals present`,
            !!body.proof && Array.isArray(body.public_signals) && body.public_signals.length === 13,
            `public_signals=${body.public_signals?.length}`);
        }
        if (name === "valid") validBody = r.text;
      }
    }

    // Multi-trap precedence: VK_SUBSTITUTION must win over recipient + threshold.
    {
      const env = makeEnvelope("multi_trap", { taskId: "gk_harness_multi_001" });
      const r = await postJson(env);
      const body = JSON.parse(r.text);
      check("multi_trap: VK_SUBSTITUTION wins precedence",
        body.decision === "REJECT" && body.reason_code === "VK_SUBSTITUTION",
        `got ${body.decision}/${body.reason_code}`);
    }

    // Idempotency: replay the `valid` task_id — byte-identical body, fast
    // (no re-prove; a fresh prove takes ~400-600 ms, a replay is a lookup).
    {
      const env = makeEnvelope("valid", { taskId: "gk_harness_valid_001" });
      const r = await postJson(env);
      check("idempotency: same task_id -> byte-identical response", r.text === validBody,
        `len ${r.text.length} vs ${validBody.length}`);
      check(`idempotency: replay fast (${r.ms} ms, no re-prove)`, r.ms < 500, `${r.ms} ms`);
    }

    // Stale task: deadline already past -> REJECT / EXPIRED_CONDITION, no proof.
    // (Fresh proof_tx: otherwise the reuse check would answer PROOF_REUSED first.)
    {
      const env = makeEnvelope("valid", { taskId: "gk_harness_stale_001", deadlineSeconds: -10 });
      env.input.proof_tx = "0x" + crypto.randomBytes(32).toString("hex");
      const r = await postJson(env);
      const body = JSON.parse(r.text);
      check("stale task: REJECT + EXPIRED_CONDITION, no proof",
        r.status === 200 && body.decision === "REJECT" && body.reason_code === "EXPIRED_CONDITION" && body.proof === undefined,
        r.text.slice(0, 200));
    }

    const maxLatency = Math.max(...latencies);
    console.log(`\nslowest task response: ${maxLatency} ms (includes first-run wasm compile + prove + mock Kurier)`);
    console.log(`harness: ${pass} passed, ${fail} failed${fail ? ` — failed: ${failures.join(", ")}` : ""}`);
    return fail === 0 ? 0 : 1;
  } finally {
    server.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 500));
    if (server.exitCode === null) server.kill("SIGKILL");
    rmSync(stateDir, { recursive: true, force: true });
    if (fail > 0) console.log("\n--- server log (tail) ---\n" + serverLog.slice(-3000));
  }
}

process.exit(await main());
