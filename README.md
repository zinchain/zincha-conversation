# Zincha Conversation Service

`zincha-conversation` is the provider-hosted, off-chain conversation service for Zincha tasks, agreements, tool jobs, and metered tool sessions. It keeps conversational traffic out of consensus while using the chain as the authority for who may read and write each conversation.

The service has no unsolicited inbox. A caller must prove an account-signed delegation and must already be a participant in the referenced on-chain workflow. The provider's service is the deterministic home for that workflow. Clients persist an outbox and retry idempotently when the home service is unavailable.

## Runtime design

- Existing participant-authorized Zincha node endpoints supply the requester, provider, parties, arbitrators, status, and terminal lifecycle timestamp. No new node endpoint or consensus rule is required.
- An account signs a bounded `ConversationKeyDelegationV1` once. The delegated Ed25519 key authenticates challenges and messages without asking a wallet to sign every conversational turn.
- The server refreshes chain authorization when its cached projection is older than the configured staleness limit. Normal message reads and writes do not call the node.
- PostgreSQL is the production store. SQLite with WAL mode is supported for one local process.
- Platform-readable payloads are encrypted at rest with XChaCha20-Poly1305 and message-bound associated data. End-to-end payloads are opaque ciphertext; the public SDKs implement X25519 + HKDF-SHA256 + XChaCha20-Poly1305 envelope encryption.
- Message IDs are idempotency keys. Per-conversation sequences, the message row, and the durable event row commit in one database transaction.
- Challenge consumption, delegation insertion, and bearer-session creation also commit in one database transaction. A conflict or database failure cannot consume a valid challenge without creating its session.
- SSE consumers subscribe before replay is read, preventing a replay/live gap. A bounded replay that cannot catch up returns `resync_required`. Long-lived streams revalidate chain-derived access on the configured interval and close with `authorization_required` when the session or authorization is no longer valid.
- Message admission, authenticated message rates, unauthenticated challenge rates, request bodies, page sizes, SSE capacity, concurrent SSE replay, broadcast buffers, database pools, and retention work are bounded.
- Retention and ephemeral cleanup run as indexed fixed-size slices. Unresolved authentication records disappear after their short session expires; expired/revoked delegations and empty terminal conversation metadata are reclaimed after their horizons. Cleanup cannot turn an aged deployment into one unbounded delete transaction.

Artifact message parts are references to content managed by the marketplace's existing task/tool artifact store. Conversation messages do not proxy unbounded files through this service.
`artifacts_after_terminal_secs` and `backups_secs` declare the matching external
artifact-store and backup policy for one deployment manifest; the daemon
enforces message and audit-row retention itself. Operators must enforce and
test the external policies in those two owning systems.

## Run

Create a 32-byte master key and keep it in a secret manager:

```sh
openssl rand -hex 32 > /run/secrets/zincha-conversation-master-key
chmod 600 /run/secrets/zincha-conversation-master-key
```

Copy [`config.example.toml`](config.example.toml), configure at least one provider signer, then run:

```sh
cargo run --release -- migrate --config conversation.toml
cargo run --release -- serve --config conversation.toml
```

The external signer contract is deliberately narrow:

- `GET /v1/identity` returns `{"address":"zn1…","public_key":"<32-byte hex>"}`.
- `POST /v1/sign` accepts `{"message_base64":"…","purpose":"zincha-rpc-signed-request-v1"}` and returns `{"signature":"<64-byte hex>"}`.

The signer should bind its listener to localhost or mutual TLS, allow only the signed-request purpose, and enforce operator policy. A raw 32-byte hex or PKCS#8 Ed25519 key file is supported for local development.
The service refuses master-key, local signer-key, and signer bearer-token files
that are not regular files or that grant group/other permissions on Unix.

## Client flow

1. Read the provider's `ConversationProfileV1` from its on-chain agent metadata and confirm over authenticated HTTPS that the service profile at `GET /v1/profile` matches.
2. Request a challenge with the account address and workflow reference.
3. Sign a bounded delegation with the account key and the challenge with its delegated operational key.
4. Create a short-lived bearer session.
5. Resolve the conversation. The service independently reads the workflow using the provider's signed-request identity and confirms both participants.
6. Sign and enqueue messages locally. Retry the same message ID until accepted.
7. Catch up with paged message reads, then follow SSE using the last durable sequence. On `resync_required`, return to paged reads; on `authorization_required`, create a new session. Acknowledge the highest processed sequence only after local processing succeeds.

See [`openapi.yaml`](openapi.yaml) for the HTTP contract. The Rust, TypeScript, and Python implementations live in [`zincha-sdk`](https://github.com/zinchain/zincha-sdk).

## Security and operations

- Terminate TLS at a trusted reverse proxy. Do not expose the plaintext listener outside the host network.
- Configure an explicit `allowed_origins` list for browser SDK callers. The service never enables wildcard credentialed CORS.
- Keep the provider signing key, payload master key, and database backups in separate security domains.
- Backups must include the database and the exact master-key version. Test restoration before reducing backup retention.
- Set retention values deliberately. The process refuses zero values.
- Rotate operational delegations rather than long-lived account keys. Revocation invalidates all sessions backed by that delegation immediately.
- Scrape `GET /metrics` for lock-free message, retry, cumulative insert-time, authorization-refresh, SSE-resync, authorization-close, maintenance-deletion, active-SSE, and in-flight-message metrics. Monitor `429` responses and retention deletion warnings alongside these bounded counters.
- Size the reverse proxy for at least the configured `max_sse_connections`; ordinary-request concurrency is isolated from long-lived streams so 10,000 idle SSE clients do not consume every message/API request slot.

## Verification

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The service tests cover authorization binding, atomic session establishment,
encrypted persistence across restart, concurrent idempotent sequencing without
gaps, immediate revocation, challenge throttling, immutable privacy modes,
payload-mode enforcement, participant-role projection, coherent chain
observation, bounded lifecycle pagination, SSE replay/live handoff and lag
recovery, bounded retention, and cryptographic context binding.

SQLite integration tests run on every local and CI invocation. PostgreSQL is
the production backend and must also pass the staging and resource gates in
[`docs/PRODUCTION_QUALIFICATION.md`](docs/PRODUCTION_QUALIFICATION.md) before a
release is promoted.

The repository also includes bounded release drivers for the two measured
capacity gates:

```sh
cargo run --release --example qualification_load -- --config load.json --output load-result.json
cargo run --release --example qualification_sse -- --config sse.json --output sse-result.json
```

Their private inputs must be mode 0600. The exact topology, evidence contract,
pass criteria, idle/active SSE split, and retention/restore checks are defined
in the production qualification document. These drivers make the gates
reproducible; passing unit tests alone is not a capacity claim.
