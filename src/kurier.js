// Kurier REST client (plan §1.5 / §5).
// POST /submit-proof/<KEY> then poll GET /job-status/<KEY>/<jobId> until
// Finalized. The poll NEVER blocks past the response deadline — the caller
// passes respondBy (epoch ms); the poll loop exits at respondBy.
//
// Mock mode (KURIER_MOCK=1): no network at all; submit returns a fake jobId
// with optimisticVerify "success" and status immediately "Finalized". The
// local test harness runs entirely in mock mode.
// NOTE: Node 24 fetch does not use this VM's egress proxy; on this VM real
// HTTPS calls to api.kurier.xyz will fail — that is expected here and covered
// by mock mode. On Fly.io (real deployment) direct HTTPS works.
import crypto from "node:crypto";
import { CONFIG } from "./config.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class KurierClient {
  constructor({ apiKey, baseUrl, mock } = {}) {
    this.apiKey = apiKey || CONFIG.kurierApiKey;
    this.baseUrl = (baseUrl || CONFIG.kurierBaseUrl).replace(/\/$/, "");
    this.mock = mock !== undefined ? mock : CONFIG.kurierMock;
  }

  async submitProof({ proof, publicSignals, vk }) {
    if (this.mock) {
      const jobId = `mock-job-${crypto.randomBytes(6).toString("hex")}`;
      return { jobId, optimisticVerify: "success", mock: true };
    }
    const res = await fetch(`${this.baseUrl}/submit-proof/${this.apiKey}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk },
      }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(`Kurier submit HTTP ${res.status}: ${JSON.stringify(body).slice(0, 300)}`);
    }
    return { jobId: body.jobId, optimisticVerify: body.optimisticVerify, raw: body };
  }

  async getJobStatus(jobId) {
    if (this.mock) return "Finalized";
    const res = await fetch(`${this.baseUrl}/job-status/${this.apiKey}/${jobId}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(`Kurier job-status HTTP ${res.status}: ${JSON.stringify(body).slice(0, 300)}`);
    }
    return body.status || body.jobStatus || "unknown";
  }

  // Poll until Finalized or until respondBy (epoch ms). Returns
  // { finalized, status, polls }. Never throws on timeout — returns
  // finalized:false so the caller can still respond with the local proof.
  async waitFinalized(jobId, respondBy, pollMs = CONFIG.kurierPollMs) {
    let status = "Submitted";
    let polls = 0;
    while (Date.now() < respondBy) {
      try {
        status = await this.getJobStatus(jobId);
        polls += 1;
      } catch (e) {
        status = `error:${e.message.slice(0, 80)}`;
      }
      if (status === "Finalized") return { finalized: true, status, polls };
      const remaining = respondBy - Date.now();
      if (remaining <= 0) break;
      await sleep(Math.min(pollMs, remaining));
    }
    return { finalized: false, status, polls };
  }
}
