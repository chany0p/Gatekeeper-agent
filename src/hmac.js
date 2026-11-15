// HMAC-SHA256 signing / verification over RAW request/response bodies.
// Primary encoding: hex (config switch HMAC_ENCODING=hex|base64 — UNVERIFIED
// until preflight confirms which the platform uses).
import crypto from "node:crypto";

export function signBody(secret, rawBody, encoding = "hex") {
  const h = crypto.createHmac("sha256", secret);
  h.update(rawBody);
  return h.digest(encoding);
}

export function verifySignature(secret, rawBody, signatureHeader, encoding = "hex") {
  if (!signatureHeader || typeof signatureHeader !== "string") return false;
  const sig = signatureHeader.trim();
  const expected = signBody(secret, rawBody, encoding);
  try {
    const a = Buffer.from(sig, encoding === "hex" ? "hex" : "base64");
    const b = Buffer.from(expected, encoding === "hex" ? "hex" : "base64");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
