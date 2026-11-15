// Central configuration. Secrets come ONLY from environment variables.
// See .env.example. Never log secret values.
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0"; // zkVerify mainnet, registered

export const CONFIG = {
  root: ROOT,
  port: parseInt(process.env.PORT || "3000", 10),
  host: process.env.HOST || "0.0.0.0",

  // TEST mode (AGENT_GAMES_TEST_MODE=1): dummy secrets allowed so the local
  // harness can run offline. PROD mode: missing secrets fail loudly at startup.
  testMode: process.env.AGENT_GAMES_TEST_MODE === "1",
  hmacSecret: process.env.AGENT_GAMES_HMAC_SECRET || null,
  kurierApiKey: process.env.KURIER_API_KEY || null,
  kurierMock: process.env.KURIER_MOCK === "1",

  // ── ONE-LINE SWITCHES (UNVERIFIED until preflight / practice) ──────────
  // HMAC signature encoding: "hex" (primary hypothesis) or "base64".
  hmacEncoding: process.env.HMAC_ENCODING || "hex",
  // Response shape: "full" = {decision, reason_code, proof, public_signals,
  // proof_tx}; "minimal" = {decision, reason_code, proof_tx}.
  responseShape: process.env.RESPONSE_SHAPE || "full",
  // taskId -> field element encoding: "keccak256" | "sha256" | "raw".
  taskIdEncoding: process.env.TASKID_ENCODING || "keccak256",
  // ────────────────────────────────────────────────────────────────────────

  wasmPath: path.join(ROOT, "artifacts", "gatekeeper.wasm"),
  zkeyPath: path.join(ROOT, "artifacts", "gatekeeper_final.zkey"),
  vkPath: path.join(ROOT, "artifacts", "gatekeeper-vk.json"),
  vkHash: VK_HASH,

  stateDir: process.env.STATE_DIR || path.join(ROOT, "state"),
  safetyMarginMs: parseInt(process.env.SAFETY_MARGIN_MS || "5000", 10), // respond by deadline_at - 5 s
  issuedSkewMs: parseInt(process.env.ISSUED_SKEW_MS || "300000", 10), // reject issued_at skew > 5 min
  kurierPollMs: parseInt(process.env.KURIER_POLL_MS || "5000", 10),
  kurierBaseUrl: process.env.KURIER_BASE_URL || "https://api.kurier.xyz/api/v1",
  maxBodyBytes: 1024 * 1024,

  // Decision int convention (UNVERIFIED — calibrate in practice):
  // APPROVE = 1, REJECT = 0.
  decisionInt: { APPROVE: 1, REJECT: 0 },
};

export function validateConfig() {
  if (CONFIG.testMode) {
    if (!CONFIG.hmacSecret) CONFIG.hmacSecret = "test-secret-dummy";
    if (!CONFIG.kurierApiKey) CONFIG.kurierApiKey = "test-key-dummy";
    if (!process.env.KURIER_MOCK) CONFIG.kurierMock = true; // offline by default in TEST mode
    return;
  }
  if (!CONFIG.hmacSecret) {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET is not set. Copy it from the Agent Games dashboard (Rotate Secret) and set it in the environment. Refusing to start in prod mode."
    );
  }
  if (!CONFIG.kurierApiKey && !CONFIG.kurierMock) {
    throw new Error(
      "KURIER_API_KEY is not set (and KURIER_MOCK != 1). Sign up at https://kurier.xyz and set the key, or set KURIER_MOCK=1 for local testing only."
    );
  }
  if (CONFIG.hmacSecret === "test-secret-dummy" || CONFIG.hmacSecret === "placeholder") {
    throw new Error(
      "AGENT_GAMES_HMAC_SECRET looks like a placeholder. Preflight will fail with a signature error — set the real platform-generated secret."
    );
  }
}
