// Proof Gatekeeper agent — node:http only, no framework.
// Routes:
//   POST /agent   — preflight + proof-gatekeeper tasks (HMAC-verified, signed replies)
//   GET  /healthz — 200, tiny (uptime / keep-alive checks)
//   anything else — 404
//
// Per-task pipeline (60 s hard deadline, plan §5):
//   1. HMAC verify over RAW body, then parse JSON.
//   2. Route by `type`; idempotency via task_id (persistent store + in-flight dedupe).
//   3. Freshness: reject work if now > deadline_at - 5 s (respond REJECT immediately).
//   4. Deterministic decision (§3 of the plan; pure comparisons, no LLM).
//   5. Local Groth16 proof (snarkjs fullProve).
//   6. Kurier submit + poll until Finalized — but NEVER past deadline_at - 5 s.
//   7. Signed response {decision, reason_code, proof, public_signals, proof_tx}
//      (proof_tx echoes the INPUT proof_tx; shape switch: RESPONSE_SHAPE).
//      If the proof could not be produced in budget, respond with the decision
//      and no proof fields — a correct decision without a valid proof
//      (+12/-3 minus the -2 proof penalty) beats a timeout (-2).
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { CONFIG, validateConfig } from "./config.js";
import { signBody, verifySignature } from "./hmac.js";
import { decide, validateInput } from "./decision.js";
import { JsonStore } from "./store.js";
import { buildCircuitInput, generateProof } from "./prover.js";
import { KurierClient } from "./kurier.js";

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), service: "gatekeeper-agent", ...obj }));
}

// Never log secrets: log only short identifiers and timings.
const short = (s) => (typeof s === "string" ? s.slice(0, 14) : s);

let seenProofs; // JsonStore: proof_tx(lower) -> { task_id, at }
let idempotency; // JsonStore: task_id -> response body object
let kurier;
let inFlight = new Map(); // task_id -> Promise<responseBody>

function jsonResponse(res, status, obj, { sign = true } = {}) {
  const body = JSON.stringify(obj);
  const headers = { "content-type": "application/json" };
  if (sign) headers["x-agent-games-signature"] = signBody(CONFIG.hmacSecret, body, CONFIG.hmacEncoding);
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > CONFIG.maxBodyBytes) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ── Preflight ──────────────────────────────────────────────────────────────
function handlePreflight(env) {
  return { ok: true, protocolVersion: "v1" };
}

// ── Task handling ──────────────────────────────────────────────────────────
async function processTask(env) {
  const startedAt = Date.now();
  const taskId = env.task_id;
  const input = env.input;
  const deadlineAt = Date.parse(env.deadline_at);
  const issuedAt = Date.parse(env.issued_at);
  const respondBy = Number.isFinite(deadlineAt)
    ? deadlineAt - CONFIG.safetyMarginMs
    : startedAt + 55000;

  const baseLog = { task_id: short(taskId) };

  // 1. Validate envelope shape.
  const inputError = validateInput(input);
  if (inputError) throw Object.assign(new Error(inputError), { status: 400 });

  // 2. Freshness: issued_at skew > 5 min, or already past respondBy.
  const stale =
    (Number.isFinite(issuedAt) && Math.abs(startedAt - issuedAt) > CONFIG.issuedSkewMs) ||
    startedAt > respondBy;

  // 3. Decision (pure comparisons; ~0.1 ms).
  const proofTxLower = String(input.proof_tx).toLowerCase();
  const proofTxSeen = seenProofs.has(proofTxLower);
  let { decision, reason_code } = decide(input, { proofTxSeen });

  // Record the proof_tx when the task is answered (any decision) — plan §3.1.
  seenProofs.set(proofTxLower, { task_id: taskId, at: new Date().toISOString() });

  // 4. Stale → REJECT immediately, no proving, no Kurier.
  if (stale) {
    if (decision === "APPROVE") {
      decision = "REJECT";
      reason_code = "EXPIRED_CONDITION"; // the task window itself expired; no TIMEOUT code exists
    }
    const body = buildResponseBody({ decision, reason_code, input, proof: null, publicSignals: null });
    log({ ...baseLog, decision, reason_code, stale: true, latencyMs: Date.now() - startedAt });
    return body;
  }

  // 5. Local proof.
  let proof = null;
  let publicSignals = null;
  let proveMs = null;
  let proveError = null;
  try {
    const circuitInput = buildCircuitInput(env, decision, reason_code);
    const r = await generateProof(circuitInput);
    proof = r.proof;
    publicSignals = r.publicSignals;
    proveMs = r.proveMs;
  } catch (e) {
    proveError = e.message.slice(0, 200);
    log({ ...baseLog, level: "warn", note: "proof generation failed", proveError });
  }

  // 6. Kurier submit + poll until Finalized, never past respondBy.
  let kurierJobId = null;
  let kurierStatus = null;
  let kurierFinalized = false;
  let kurierPolls = 0;
  if (proof) {
    try {
      const sub = await kurier.submitProof({ proof, publicSignals, vk: CONFIG.vkHash });
      kurierJobId = sub.jobId;
      if (sub.optimisticVerify !== "success") {
        log({
          ...baseLog,
          level: "warn",
          note: "kurier optimisticVerify != success",
          optimisticVerify: sub.optimisticVerify,
        });
      } else {
        const w = await kurier.waitFinalized(kurierJobId, respondBy);
        kurierStatus = w.status;
        kurierFinalized = w.finalized;
        kurierPolls = w.polls;
      }
    } catch (e) {
      log({ ...baseLog, level: "warn", note: "kurier error", error: e.message.slice(0, 200) });
    }
  }

  const body = buildResponseBody({ decision, reason_code, input, proof, publicSignals });
  log({
    ...baseLog,
    decision,
    reason_code,
    proveMs,
    kurierJobId: kurierJobId ? short(kurierJobId) : null,
    kurierStatus,
    kurierFinalized,
    kurierPolls,
    latencyMs: Date.now() - startedAt,
  });
  return body;
}

// Response shape switch (UNVERIFIED until practice):
// full:    {decision, reason_code, proof, public_signals, proof_tx}
// minimal: {decision, reason_code, proof_tx}
// proof_tx echoes the INPUT proof_tx (the incoming proof's reference), per
// /build §02 — it is NOT the agent's own Kurier reference.
function buildResponseBody({ decision, reason_code, input, proof, publicSignals }) {
  const base = { decision, reason_code, proof_tx: input.proof_tx };
  if (CONFIG.responseShape === "minimal") return base;
  if (proof && publicSignals) {
    return { decision, reason_code, proof, public_signals: publicSignals, proof_tx: input.proof_tx };
  }
  return base; // proof unavailable: decision only (still better than a timeout)
}

async function handleAgent(req, res, rawBody) {
  // HMAC over the RAW body BEFORE any JSON parsing.
  if (!verifySignature(CONFIG.hmacSecret, rawBody, req.headers["x-agent-games-signature"], CONFIG.hmacEncoding)) {
    return jsonResponse(res, 401, { error: "invalid_signature" });
  }
  let env;
  try {
    env = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return jsonResponse(res, 400, { error: "invalid_json" });
  }
  if (!env || typeof env !== "object" || typeof env.type !== "string") {
    return jsonResponse(res, 400, { error: "invalid_envelope" });
  }

  if (env.type === "agent-games.preflight.v1") {
    return jsonResponse(res, 200, handlePreflight(env));
  }
  if (env.type !== "agent-games.proof-gatekeeper.v1") {
    return jsonResponse(res, 400, { error: "unknown_type", type: env.type });
  }
  if (!env.task_id || typeof env.task_id !== "string" || !env.input) {
    return jsonResponse(res, 400, { error: "invalid_envelope" });
  }

  // Idempotency: repeat task_id returns the stored response, never re-proves.
  const stored = idempotency.get(env.task_id);
  if (stored) {
    log({ task_id: short(env.task_id), note: "idempotent replay" });
    return jsonResponse(res, 200, stored);
  }
  // Concurrent duplicate delivery: await the in-flight computation.
  if (inFlight.has(env.task_id)) {
    const body = await inFlight.get(env.task_id);
    return jsonResponse(res, 200, body);
  }

  const p = (async () => {
    const body = await processTask(env);
    idempotency.set(env.task_id, body);
    return body;
  })();
  inFlight.set(env.task_id, p);
  try {
    const body = await p;
    return jsonResponse(res, 200, body);
  } catch (e) {
    const status = e.status || 500;
    log({ task_id: short(env.task_id), level: "error", note: "task failed", error: e.message.slice(0, 200) });
    return jsonResponse(res, status, { error: status === 400 ? e.message : "internal" });
  } finally {
    inFlight.delete(env.task_id);
  }
}

// ── Server ─────────────────────────────────────────────────────────────────
export function createServer() {
  return http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && req.url === "/healthz") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, service: "gatekeeper-agent", version: "1.0.0" }));
        return;
      }
      if (req.method === "POST" && req.url === "/agent") {
        const rawBody = await readBody(req);
        await handleAgent(req, res, rawBody);
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
    } catch (e) {
      log({ level: "error", note: "request failed", error: e.message.slice(0, 200) });
      try {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal" }));
      } catch {
        /* socket already gone */
      }
    }
  });
}

function main() {
  validateConfig();
  for (const f of [CONFIG.wasmPath, CONFIG.zkeyPath]) {
    if (!fs.existsSync(f)) throw new Error(`missing artifact: ${f}`);
  }
  seenProofs = new JsonStore(path.join(CONFIG.stateDir, "seen-proofs.json"));
  idempotency = new JsonStore(path.join(CONFIG.stateDir, "idempotency.json"));
  kurier = new KurierClient();
  const server = createServer();
  server.listen(CONFIG.port, CONFIG.host, () => {
    log({
      note: "listening",
      host: CONFIG.host,
      port: CONFIG.port,
      testMode: CONFIG.testMode,
      kurierMock: kurier.mock,
      hmacEncoding: CONFIG.hmacEncoding,
      responseShape: CONFIG.responseShape,
      seenProofs: seenProofs.size(),
      idempotency: idempotency.size(),
    });
  });
}

main();
