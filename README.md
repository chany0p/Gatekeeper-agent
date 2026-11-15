# Proof Gatekeeper Agent — zkVerify Agent Games

Deterministic Groth16 gatekeeper agent for the **Proof Gatekeeper** track
(100,000 VFY). Node.js ESM, `node:http` only, no framework, no LLM anywhere
in the decision path — every decision is pure comparison logic, and every
proof is generated locally with snarkjs and verified by the circuit itself.

## How it works

1. Platform POSTs a signed task to `POST /agent` (`agent-games.proof-gatekeeper.v1`).
2. Agent verifies the HMAC over the **raw** body, parses the envelope, and
   decides **APPROVE/REJECT** with a `reason_code` (7 trap types, fixed
   precedence — see `src/decision.js`).
3. Agent generates a Groth16 proof locally (`snarkjs fullProve`), submits it
   to zkVerify via **Kurier REST**, polls until `Finalized` — but never past
   `deadline_at − 5 s`.
4. Agent responds `{decision, reason_code, proof, public_signals, proof_tx}`
   (proof_tx echoes the input's proof_tx), signed with
   `x-agent-games-signature`.

Preflight (`agent-games.preflight.v1`) is answered with
`{ok: true, protocolVersion: "v1"}`, signed. `GET /healthz` returns 200.

## Circuit mapping — RESOLVED (was the #1 unknown)

The circuit source (`.circom`) is unpublished, so the input signal names were
discovered by probing `gatekeeper.wasm` (Circom 2 hashes signal names with
FNV-1a; `getInputSignalSize` returns 1 for a real input, 0 otherwise).
Scripts: `scripts/probe-signals.mjs`.

**13 inputs** (`getInputSize() == 13`, template `GatekeeperEvaluation_79`):

| signal | value |
|---|---|
| `registeredVkHash`, `proofVkHash` | envelope vk values as field elements (mod BN128 prime) |
| `minimum`, `publicBalance`, `expiryBlock`, `currentBlock` | envelope numbers |
| `recipient`, `conditionRecipient` | envelope addresses as field elements |
| `amount`, `maxTransfer` | envelope numbers |
| `decision` | **APPROVE = 1, REJECT = 0** |
| `salt` | **PRIVATE** input — agent-chosen randomness (default random 128-bit) |
| `taskId` | `keccak256(task_id)` as a field element |

**13 public signals** (witness order): `[0]` is a public **output**,
`Poseidon([salt, taskId])` — a commitment binding the proof to the task
without revealing the salt; `[1..12]` are the inputs above except `salt`
(`registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
taskId`).

**Decision enforcement — verified locally** (`scripts/probe-proof.mjs --matrix`,
8/8): the circuit asserts (line 102) that the decision follows from the field
checks. A **wrong decision fails at witness generation** (`Assert Failed`) —
it cannot even produce a bad proof. Correct decisions prove in **~0.4 s warm
(~1.1–1.3 s cold, first proof in a process, incl. wasm compile)** and verify
against the exported vk (`artifacts/gatekeeper-vk.json`, nPublic 13).

**Consequence — PROOF_REUSED has no proof:** reuse is off-chain state, not
a circuit input, so a REJECT on field-valid inputs cannot be proven. The
server answers REJECT with **no proof fields** for that case (correct
decision +12/−3, minus a possible −2 proof penalty — the best achievable).

## UNVERIFIED — calibrate in practice mode

These are the remaining unknowns. Each is a **one-line switch**; change only
after practice-mode feedback (the practice dashboard shows expected decision,
what the agent submitted, and a mismatch explanation):

| item | current default | switch | how to calibrate |
|---|---|---|---|
| HMAC algorithm/encoding | HMAC-SHA256 **hex** | `HMAC_ENCODING=hex\|base64` | Preflight: `protocol` error = wrong encoding; try the other. |
| Response shape | **full** `{decision, reason_code, proof, public_signals, proof_tx}` | `RESPONSE_SHAPE=full\|minimal` | Practice feedback: if extra fields are rejected, use `minimal`. |
| taskId encoding | **keccak256**(task_id) | `TASKID_ENCODING=keccak256\|sha256\|raw` | Practice feedback: if the platform's expected `publicSignals[12]` differs, try `raw` (UTF-8 bytes as BigInt) or `sha256`. |
| Reason-code precedence | VK > RECIPIENT > THRESHOLD > AMOUNT > EXPIRED > REUSED > VALID | `src/decision.js` `decide()` | Dispatch co-occurring traps in practice; reorder to match expected codes. |
| Incoming-proof confirmation | v1 decides on field checks + reuse set only (lookup endpoint undocumented) | — | If practice marks VALID tasks wrong, revisit (§3.2 of the plan). |

## Setup

```sh
npm ci
cp .env.example .env   # fill in the two secrets below, never commit .env
```

| env var | required | notes |
|---|---|---|
| `AGENT_GAMES_HMAC_SECRET` | prod | Dashboard → agent → **Rotate Secret** (shown once). A placeholder fails preflight. |
| `KURIER_API_KEY` | prod | Sign up at https://kurier.xyz (mainnet). |
| `KURIER_MOCK=1` | testing | Skips real Kurier calls (fake jobId, instant Finalized). Default on in TEST mode. |
| `AGENT_GAMES_TEST_MODE=1` | testing | Allows dummy secrets; defaults Kurier to mock. **Never in prod.** |
| `HMAC_ENCODING`, `RESPONSE_SHAPE`, `TASKID_ENCODING` | no | Switches above (defaults: `hex`, `full`, `keccak256`). |
| `PORT`, `HOST` | no | Defaults `3000`, `0.0.0.0`. |
| `STATE_DIR` | no | JSON stores (seen proofs, idempotency). Default `./state`. |

Prod mode **refuses to start** without `AGENT_GAMES_HMAC_SECRET` (and
without `KURIER_API_KEY` unless `KURIER_MOCK=1`).

## Local test

```sh
npm test            # full harness: preflight, 401s, 7 trap fixtures,
                    # precedence, idempotency, stale task — 44 checks
npm run probe -- --matrix   # circuit calibration matrix (8 cases)
node scripts/probe-proof.mjs valid                 # one proof + verify
node scripts/probe-proof.mjs path/to/task.json --decision 1
AGENT_GAMES_TEST_MODE=1 node src/server.js        # run the server directly
```

Fixture note: all test fixtures share one `proof_tx` on purpose — precedence
must still yield each fixture's own reason code (see `test/fixtures.mjs`).

**Measured on this VM:** fullProve **~0.35–0.65 s warm, ~1.1–1.3 s cold**;
slowest harness task response **~1.3 s** (first-run wasm compile + prove +
mock Kurier) — far inside the 60 s window. Idempotent replay: **2–5 ms**.

## Deploy (Fly.io)

```sh
fly launch --name <your-app> --region sin --no-deploy   # or edit fly.toml
fly secrets set AGENT_GAMES_HMAC_SECRET=<from dashboard> KURIER_API_KEY=<from kurier.xyz>
fly deploy
fly status   # 1 machine, always on: min_machines_running=1, auto_stop_machines=false
curl https://<your-app>.fly.dev/healthz
```

Then on the Agent Games dashboard: **register the agent** (name, event:
Proof Gatekeeper, repository URL = this repo on your personal GitHub, endpoint
`https://<your-app>.fly.dev/agent`) — saving the endpoint runs a signed
**preflight**; it must pass before the agent is marked active. Then **practice
mode**: dispatch all 7 trap types, calibrate the switches above, then **enter
Proof Gatekeeper**.

> This VM has no inbound path and its Node `fetch` does not use the egress
> proxy — real Kurier HTTPS calls fail from here. That is expected: the mock
> mode covers local tests; on Fly.io direct HTTPS works. Do not "fix" the
> service to work around VM networking.

## Layout

```text
src/server.js        HTTP service: /agent (+preflight), /healthz, HMAC, idempotency
src/config.js        env + one-line UNVERIFIED switches + prod startup guards
src/hmac.js          HMAC-SHA256 sign/verify (timing-safe)
src/decision.js      the 7 deterministic checks + precedence (no LLM)
src/prover.js        buildCircuitInput() — THE mapping (single function) + fullProve
src/kurier.js        Kurier submit + poll-until-Finalized (deadline-bounded) + mock
src/store.js         JSON stores with fsync-on-write (seen proofs, idempotency)
scripts/probe-proof.mjs     proof calibration probe (+ --matrix)
scripts/probe-signals.mjs   wasm signal-name discovery probe
scripts/test-harness.mjs    offline end-to-end harness (npm test)
test/fixtures.mjs    §1.1 sample envelope + 7 trap fixtures (+ multi-trap)
artifacts/           gatekeeper.wasm, gatekeeper_final.zkey, gatekeeper-vk.json
Dockerfile, fly.toml deploy skeletons
```

## Security notes

- Secrets only from env; never logged (logs carry task_id prefixes, decisions,
  timings, Kurier jobIds only). `.env`, `state/`, `node_modules/` are gitignored.
- Fail closed: stale/uncertain work is REJECTed, never approved by default;
  a failed proof still returns the (correct) decision rather than timing out.
- `task_id` is the idempotency key (persistent store + in-flight dedupe);
  `proof_tx` values are kept in a persistent seen-set (recorded on any answer).
- Kurier submission uses the **already-registered** gatekeeper vk
  (`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`,
  zkVerify mainnet) with `vkRegistered: true` — no `register-vk` call needed.
