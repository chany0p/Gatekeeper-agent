# Proof Gatekeeper agent — zkVerify Agent Games
FROM node:24-slim

WORKDIR /app

# Install dependencies first (cached layer) …
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

# … then the app + circuit artifacts.
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY test/ ./test/
COPY artifacts/ ./artifacts/

# Circuit binaries (gatekeeper.wasm + gatekeeper_final.zkey) cannot be pushed
# through the GitHub connector (binary files), so fetch them from the official
# /build artifacts page at image build time and verify their pinned hashes.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o artifacts/gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm \
 && curl -fsSL -o artifacts/gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey \
 && echo "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f  artifacts/gatekeeper.wasm" | sha256sum -c - \
 && echo "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d  artifacts/gatekeeper_final.zkey" | sha256sum -c -

# The service listens on $PORT (Fly sets it automatically).
ENV NODE_ENV=production
EXPOSE 3000

# Secrets come from the environment (Fly secrets / .env), never baked in.
CMD ["node", "src/server.js"]
