# Production Qualification

This procedure measures the release gates for `zincha-conversation`. Unit and
integration tests establish correctness; they do not establish production
capacity. A release is qualified only when the signed result bundle from this
procedure passes on the declared production topology.

## Fixed topology and evidence

Use the intended production database and each advertised transport. Record the service commit,
Rust version, lockfile hash, optimized binary hash, configuration hash, schema
version, host shape, database shape, kernel, and start/end timestamps. Keep
secrets outside the evidence bundle.

For every run capture:

- accepted and offered messages, durable sequence span, error classes, and
  p50/p95/p99 client latency;
- service CPU%, CPU seconds per accepted message, current RSS, RSS high-water,
  event-loop lag, in-flight inserts, active SSE streams, and resync counts;
- PostgreSQL transaction rate, commit latency, connection occupancy, WAL rate,
  table/index growth, lock waits, checkpoints, and storage throttling;
- retention rows eligible, visited, and deleted before and after the run;
- reverse-proxy connection count, direct-TLS active connections, handshakes,
  failures, timeouts and cumulative latency, connection-capacity rejection
  count, and network errors.

Do not repair or omit a failed observation. A missing metric or incomplete
sequence span is an inconclusive run.

## Correctness prerequisite

Run the repository checks with a real PostgreSQL 16 instance:

```sh
export ZINCHA_TEST_POSTGRES_URL='postgres://.../zincha_conversation_test'
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

Exercise backup restore with the exact payload-master-key version. After
restore, verify authentication, encrypted payload reads, idempotent retry, SSE
resume, revocation, and retention on the restored database.

Run the correctness matrix independently through Web-PKI HTTPS and
`zincha-tls-v1`, then with mixed API/SSE traffic. Verify TLS 1.2, plaintext,
early data, malformed/expired/future/removed pins, wrong service IDs, and stale
live profiles fail before credentials or workflow identifiers are sent. Run
the old-only, overlap with the old certificate active, overlap with the new
certificate active, new-only, and old-certificate-rejected rotation phases.

## Message-throughput gate

Prepare a fresh workflow/conversation and a delegation that remains valid for
the complete run. Put this private input in a mode-0600 file:

```json
{
  "profile": {
    "version": 2,
    "service_id": "provider-agent/conversations",
    "interfaces": [
      {
        "type": "zincha_tls_v1",
        "host": "203.0.113.25",
        "port": 443,
        "certificate_pins": [
          {
            "sha256": "<64-lowercase-hex-leaf-certificate-fingerprint>",
            "not_before_ms": 1791000000000,
            "not_after_ms": 1822536000000
          }
        ]
      },
      { "type": "https", "url": "https://conversations.example.com" }
    ],
    "privacy_modes": ["platform_readable", "end_to_end"],
    "protocol_versions": [1]
  },
  "transport_policy": "zincha_tls_only",
  "provider_address": "zn1...",
  "delegation": { "version": 1 },
  "operational_secret_hex": "<32-byte-secret>",
  "rate_per_second": 1000,
  "duration_seconds": 1800,
  "max_inflight": 512,
  "message_text": "zincha conversation qualification"
}
```

The qualification deployment must set
`limits.messages_per_second_per_participant` to at least the declared offered
rate because this driver intentionally measures one hot participant and one
conversation. Record the override in the evidence manifest. Keep the secure
production default unchanged for ordinary deployments, and do not interpret a
rate-limit rejection as service capacity.

The `delegation` value is the complete account-signed
`ConversationKeyDelegationV1`. The driver refuses a pre-existing conversation,
keeps response/error/sample memory bounded, rotates short-lived sessions, and
never writes the secret or bearer token to its report.

```sh
chmod 600 qualification-load.json
cargo run --release --example qualification_load -- \
  --config qualification-load.json \
  --output qualification-load-result.json
```

Pass requires 1,800,000 offered messages, no client saturation, no request
errors, 100% acceptance, a durable contiguous sequence span of 1,800,000, and
no growing eligible retention/event backlog. The service and database resource
observations must remain within the deployment's predeclared CPU, RSS, latency,
and storage budgets.

Repeat this 30-minute gate for HTTPS-only, pinned-TLS-only, and predeclared
mixed traffic. Compare CPU seconds per accepted message and warmed/high-water
RSS with the unchanged HTTP application baseline; any material regression or
growing handshake/backlog debt leaves qualification pending.

The driver consumes the authenticated on-chain profile and verifies the live
`/v1/profile` response before requesting a challenge. Set `transport_policy`
to `https_only` or `zincha_tls_only` for the isolated arms. Run both predeclared
arms concurrently for the mixed arm; do not use `auto` to manufacture a mixed
workload. `auto` is for ordered reachability fallback testing.

## SSE connection and fan-out gate

Use two fresh workflows so the idle population does not receive traffic meant
for the active subset. Create short-lived sessions whose expiry is later than
the ramp plus hold interval. Each mode-0600 input has this form:

```json
{
  "profile": {
    "version": 2,
    "service_id": "provider-agent/conversations",
    "interfaces": [
      {
        "type": "zincha_tls_v1",
        "host": "203.0.113.25",
        "port": 443,
        "certificate_pins": [
          {
            "sha256": "<64-lowercase-hex-leaf-certificate-fingerprint>",
            "not_before_ms": 1791000000000,
            "not_after_ms": 1822536000000
          }
        ]
      },
      { "type": "https", "url": "https://conversations.example.com" }
    ],
    "privacy_modes": ["platform_readable", "end_to_end"],
    "protocol_versions": [1]
  },
  "transport_policy": "zincha_tls_only",
  "conversation_id": "<64-lowercase-hex>",
  "access_token": "<short-lived-token>",
  "connections": 9900,
  "ramp_per_second": 1000,
  "hold_seconds": 600,
  "after": 0
}
```

Run 9,900 idle streams and 100 active streams concurrently. Run a bounded
message driver against only the active conversation during the hold interval.
Raise the load-generator file-descriptor limit before starting.

The SSE driver shards streams across bounded HTTP client pools at the direct
listener's declared 128-stream HTTP/2 limit. It reuses one pooled TLS
connection per shard where HTTP/2 is available, rather than paying one TLS
handshake per SSE stream. The report records `client_pools`; compare that with
the service handshake counters and reject unexplained excess handshakes. Its
request deadline covers the complete declared ramp, hold interval, and a
60-second connection margin.

```sh
cargo run --release --example qualification_sse -- \
  --config qualification-sse-idle.json \
  --output qualification-sse-idle-result.json

cargo run --release --example qualification_sse -- \
  --config qualification-sse-active.json \
  --output qualification-sse-active-result.json
```

Pass requires all 10,000 streams to connect and remain until the deadline,
zero stream errors, zero `resync_required` and `authorization_required` events,
and the expected message event count for the active subset. RSS must reach a
bounded plateau. Reconnect the population in a predeclared ramp after a proxy
restart and verify that replay concurrency stays within configuration and
ordinary API requests remain responsive.

Repeat connection churn during a certificate overlap and after the old pin is
removed. Existing pooled sessions may finish under an advertised pin; new
connections must observe the current on-chain pin set, and retired-pin session
resumption must not succeed.

## Authorization and retention gates

During a sustained message run, record chain RPC requests. Refresh traffic must
scale with active conversations divided by the configured authorization
staleness interval, not with message rate. Verify that concurrent stale
requests for one conversation share a single chain refresh and that 10,000 SSE
revalidation timers do not create synchronized database or chain-RPC bursts.
Change and revoke participant access on-chain and verify that the next bounded
refresh closes affected streams and rejects reads/writes.

Age a terminal fixture beyond every configured horizon. Run bounded maintenance
slices until no eligible rows remain. Verify message/event deletion, expired
session/challenge/delegation cleanup, empty conversation reclamation, artifact
store policy, and backup policy independently. New writes and reads must remain
responsive while cleanup runs.

## Promotion record

Store the immutable manifests, raw resource series, driver JSON reports,
PostgreSQL observations, restore evidence, and a pass/fail decision together.
The promotion record must distinguish implementation completeness from measured
qualification. No release note may claim the 1,000-message/s or 10,000-SSE
target until this procedure has passed on the declared production topology.
