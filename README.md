# Zincha Conversation Service

`zincha-conversation` is the provider-hosted, off-chain conversation service for Zincha tasks, agreements, tool jobs, and metered tool sessions. It keeps conversational traffic out of consensus while using the chain as the authority for who may read and write each conversation.

The service has no unsolicited inbox. A caller must prove an account-signed delegation and must already be a participant in the referenced on-chain workflow. The provider's service is the deterministic home for that workflow. Clients persist an outbox and retry idempotently when the home service is unavailable.

## Runtime design

- Existing private workflow endpoints supply the requester, provider, parties,
  arbitrators, status, and terminal lifecycle timestamp. A bounded on-chain
  grant lets the service read them as the provider without holding the
  provider's key or calling a provider-hosted signer.
- An account signs a bounded `ConversationKeyDelegationV1` once. The delegated Ed25519 key authenticates challenges and messages without asking a wallet to sign every conversational turn.
- The server refreshes chain authorization when its cached projection is older than the configured staleness limit. Concurrent stale requests for one conversation share one in-flight refresh, and normal message reads and writes do not call the node.
- PostgreSQL is the production store. SQLite with WAL mode is supported for one local process.
- Platform-readable payloads are encrypted at rest with XChaCha20-Poly1305 and message-bound associated data. End-to-end payloads are opaque ciphertext; the public SDKs implement X25519 + HKDF-SHA256 + XChaCha20-Poly1305 envelope encryption.
- Message IDs are idempotency keys. Per-conversation sequences, message rows, and durable event rows commit atomically. PostgreSQL commits each bounded, configurable admission micro-batch with one set-based statement across its active conversations. It locks conversation rows in canonical order, allocates an independent contiguous sequence for each conversation, and amortizes WAL commit without changing the single-message HTTP contract. The worker uses one connection reserved from the configured pool so admission reads cannot starve durable progress. Retry conflicts remain isolated to their request while other valid messages in the same commit receive their own results. SQLite keeps its direct single-process write path.
- Challenge consumption, delegation insertion, and bearer-session creation also commit in one database transaction. A conflict or database failure cannot consume a valid challenge without creating its session.
- SSE consumers subscribe before replay is read, preventing a replay/live gap. A bounded replay that cannot catch up returns `resync_required`. Long-lived streams revalidate chain-derived access on randomized points within the configured interval, avoiding synchronized refresh bursts, and close with `authorization_required` when the session or authorization is no longer valid.
- Message admission, authenticated message rates, unauthenticated challenge rates, request bodies, page sizes, SSE capacity, concurrent SSE replay, broadcast buffers, database pools, and retention work are bounded.
- Retention and ephemeral cleanup run as indexed fixed-size slices. Unresolved authentication records disappear after their short session expires; expired/revoked delegations and empty terminal conversation metadata are reclaimed after their horizons. Cleanup cannot turn an aged deployment into one unbounded delete transaction.
- One service instance may expose the same router and database through ordinary Web-PKI HTTPS, direct `zincha-tls-v1`, or both. Direct transport is HTTP/1.1 or HTTP/2 over TLS 1.3; clients authenticate its leaf certificate against pins in the provider's on-chain profile.

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

Generate the service's dedicated chain-read key. This key is separate from TLS,
message encryption, and the at-rest master key:

```sh
zincha-conversation chain-read-key generate \
  --secret-key /run/secrets/zincha-chain-read-key.hex
```

The command refuses to overwrite a file, creates it with mode 0600 on Unix,
and prints only the public key and address. Copy
[`config.example.toml`](config.example.toml), point
`chain.chain_read_key.active_secret_key_file` at that file, then run:

```sh
cargo run --release -- migrate --config conversation.toml
cargo run --release -- serve --config conversation.toml
```

For a direct pinned endpoint, generate an Ed25519 certificate for the public IP
and export the exact canonical profile bytes that must be published in agent
metadata:

```sh
zincha-conversation certificate generate \
  --host 203.0.113.25 \
  --certificate /etc/zincha-conversation/tls/certificate.pem \
  --private-key /run/secrets/zincha-conversation-tls-key.pem
zincha-conversation profile export --config conversation.toml --output conversation-profile.json
```

Prepare an independent next identity for a two-pin rotation with:

```sh
zincha-conversation certificate rotate \
  --host 203.0.113.25 \
  --next-certificate /etc/zincha-conversation/tls/next-certificate.pem \
  --next-private-key /run/secrets/zincha-conversation-next-tls-key.pem
```

Set `next_certificate_file`, export and finalize the overlap profile, then
change the active certificate/key paths to the generated pair and restart the
service. After both interfaces verify and caches have expired, remove the old
pin from the on-chain profile. The command only creates new files and refuses
to overwrite an existing identity.

The public `zincha-tls-v1` default is TCP 443. The listener also defaults to
`0.0.0.0:443`; an operator can instead bind an unprivileged internal port and
map `443:<internal-port>` through a container or router. The private plaintext
backend remains `127.0.0.1:9988` for local development and HTTPS reverse
proxies and must never be advertised as a public interface. For IPv6, place the
canonical literal address in `host` without brackets; clients add brackets when
constructing the URL.

The chain-read key may be raw 32-byte lowercase hex or PKCS#8 Ed25519 PEM. The
service refuses master-key and chain-read-key files that are not private regular
files. There is no `/v1/identity` or `/v1/sign` callback, provider signer token,
or per-provider signer map.

## Client flow

1. Read the provider's `ConversationProfileV2` from authenticated on-chain agent metadata. Select the first supported interface in provider order and require `GET /v1/profile` to match the on-chain bytes exactly before sending a credential or workflow identifier.
2. Read `GET /v1/delegation-info`, submit the generated scoped grant transaction
   for the active key, and wait for finality. The SDK defaults to 30 days.
3. Request a challenge with the account address and workflow reference.
4. Sign a bounded conversation-key delegation with the account key and the
   challenge with its delegated operational key.
5. Create a short-lived bearer session.
6. Resolve the conversation. The service signs its own delegated node reads;
   the node resolves the grant to the provider and applies the existing
   participant checks.
7. Sign and enqueue messages locally. Retry the same message ID until accepted.
8. Catch up with paged message reads, then follow SSE using the last durable sequence. On `resync_required`, return to paged reads; on `authorization_required`, create a new session. Acknowledge the highest processed sequence only after local processing succeeds.

See [`openapi.yaml`](openapi.yaml) for the HTTP contract. The Rust, TypeScript, and Python implementations live in [`zincha-sdk`](https://github.com/zinchain/zincha-sdk).

## Security and operations

- Use Web-PKI HTTPS behind a trusted reverse proxy, direct pinned `zincha-tls-v1`, or both. Do not expose the plaintext backend outside the host network.
- Direct TLS permits one active and one next certificate pin. Rotate by publishing both pins, waiting for chain finality and profile-cache expiry, activating the new certificate, verifying both advertised interfaces, and then publishing only the new pin. A pin mismatch is a terminal security error and never triggers fallback.
- Binding port 443 directly under systemd requires `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. Container deployments can use `-p 443:8443` with `listen = "0.0.0.0:8443"`. Open TCP 443 for both IPv4 and IPv6 where advertised.
- Configure an explicit `allowed_origins` list for browser SDK callers. The service never enables wildcard credentialed CORS.
- Keep the chain-read key, payload master key, TLS key, and database backups in
  separate security domains. The provider account key remains with the
  provider.
- Backups must include the database and the exact master-key version. Test restoration before reducing backup retention.
- Set retention values deliberately. The process refuses zero values.
- Keep `authorization_max_staleness_secs` at or below the enforced 60-second
  ceiling. Lifecycle workers invalidate revoked and expired grants immediately;
  this ceiling bounds stale authorization if a worker or node query is unavailable.
- Rotate operational conversation delegations rather than long-lived account
  keys. Revocation invalidates all sessions backed by that delegation
  immediately. Rotate the service chain-read key by exposing a next key,
  collecting grants, promoting it, retaining the old key as previous during the
  bounded migration window, then revoking old grants and removing the key.
- Scrape `GET /metrics` for lock-free message, retry, cumulative insert-time, authorization-refresh, SSE-resync, authorization-close, maintenance-deletion, active-SSE, in-flight-message, TLS connection/handshake/rejection, and current/maximum event-loop-lag metrics. TLS labels contain only the bounded transport name. Direct TLS retains one connection permit per live socket and caps sockets at the configured SSE capacity plus ordinary-request capacity. Monitor `429` responses and retention deletion warnings alongside these counters.
- Size the reverse proxy for at least the configured `max_sse_connections`; ordinary-request concurrency is isolated from long-lived streams so 10,000 idle SSE clients do not consume every message/API request slot.
- Start from [`deploy/haproxy-https.cfg.example`](deploy/haproxy-https.cfg.example) when a Web-PKI proxy must serve a large SSE population. It terminates public TLS and multiplexes streams to the service's private HTTP/2 listener, avoiding one backend socket and its service-side state per downstream stream. Normal access logging is disabled in both proxy examples; bounded service metrics cover routine traffic while proxy warnings and errors remain available without placing every conversation path on the request-critical logging path. [`deploy/nginx-https.conf.example`](deploy/nginx-https.conf.example) remains suitable when that extra SSE socket/RSS cost is provisioned. Both examples preserve long request lifetimes so connection rotation does not make a running stream depend on fresh DNS resolution.

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
observation, bounded lifecycle pagination, shared stale-authorization refresh,
delegated-request key selection, terminal security failures, persisted
lifecycle cursors, revocation/expiry cache invalidation,
SSE replay/live handoff and lag recovery, bounded retention, cryptographic
context binding, and rejection of non-contributory X25519 public keys. A
cross-repository integration test starts the real pinned-TLS service and uses
the pinned public Rust SDK as independently authenticated requester and
provider agents. It verifies bidirectional live delivery, signed replies,
idempotent retry, acknowledgements, and identical durable message history.

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
