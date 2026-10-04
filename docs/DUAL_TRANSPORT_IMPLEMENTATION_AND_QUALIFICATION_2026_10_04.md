# Dual HTTPS and `zincha-tls-v1` implementation and qualification

Date: 2026-10-04

## Decision and scope

The conversation service implements HTTPS and `zincha-tls-v1` as two trust
variants of the same bounded HTTP API. HTTPS uses Web-PKI identity. The pinned
transport uses TLS 1.3 and authenticates the leaf certificate against pins in
the provider's authenticated on-chain `ConversationProfileV2`. Both listeners
share one router, service state, database, sequence space, SSE stream and
retention worker.

This branch does not change `zincha-node` consensus or execution. Agent
metadata remains opaque and bounded on chain. The Rust, TypeScript/Node and
Python SDKs implement the matching profile and transport behavior in their
respective repositories.

## Exact source revisions

| Component | Branch | Revision |
| --- | --- | --- |
| Conversation service and final mixed qualification runtime | `codex/conversation-system` | `5d84003e717bceaa5127caa088dd940aa2c2b677` |
| Qualification SSE harness | `codex/conversation-system` | `be3ce8e130121b74399a8eede511e3d3043b54f0` |
| Public SDKs | `codex/conversation-system` | `29bc9f20fd82be069bd770a212695ef89da93ac8` |
| `zincha-dev` embedded SDK/docs | `codex/conversation-system` | `407a54a29582fea527a72cd3d39e9591959ca1f7` |

The optimized Linux package for the current service source is
`zincha-conversation-5d84003-linux-x86_64.tar.gz`, SHA-256
`ac16b22b65896dbe01c06feea21d3b9b81fb4c984b2d9c2f50d057ebf3016aa5`.
It was built for `x86_64-unknown-linux-gnu` with Rust 1.94.0, Cargo 1.94.0,
Zig 0.16.0 and the locked dependency graph. The package contains its build
manifest and per-file hashes. The service and load binaries have SHA-256
`d865653fa043a85777632ade19076a288cbbe0161be936e0fb56849ed7d715b1`
and `9bfb0c9690ae175fdfee3fc85683b5fa78bed19c6cef8229922839a8753d5337`.

The final SSE qualification harness is built from `be3ce8e`; its Linux
`qualification_sse` binary has SHA-256
`145eae39c3de2a92d61930629c6022912786e807f9a7d40fdac06059be80af26`.
The service and load-generator binaries used in the final run match the package
hashes exactly.

## Implemented behavior

- `ConversationProfileV2` supports ordered `zincha_tls_v1` and `https`
  interfaces, canonical literal IP addresses, an explicit resolved port,
  one active plus one next leaf-certificate pin, exact-field validation and
  the existing 4-KiB metadata bound.
- The direct listener enforces TLS 1.3, disables early data, advertises HTTP/2
  and HTTP/1.1, bounds handshakes, connections, HTTP/2 streams and windows,
  and applies a handshake timeout.
- Certificate generation, rotation and exact canonical profile export are
  available from the service CLI. Startup verifies the key/certificate pair,
  certificate validity and pin correspondence.
- SDK policy is `Auto`, `HttpsOnly` or `ZinchaTlsOnly`. Auto fallback is
  limited to reachability failures. Pin, certificate, service identity and
  live-profile failures are terminal.
- Each client validates `/v1/profile` exactly before sending a challenge,
  bearer token, delegation, workflow identifier or message. Pins come only
  from authenticated chain metadata.
- Rust, Node and Python provide pinned transports on the same socket used for
  HTTP. Browser TypeScript supports HTTPS and reports pinned-only profiles as
  unsupported.
- Sessions, signed messages, idempotency, global sequencing, SSE replay and
  retention are independent of transport.

## Throughput correction made during qualification

The original single-message PostgreSQL path performed several application to
database round trips while holding the hot conversation row lock. A
server-side atomic ingest function improved a one-conversation 1,000-message/s
screen from 435.197 to 656.157 accepted messages/s. A bounded 16-message,
2-millisecond service batch and a dedicated durable-writer connection then
removed the remaining round trips and pool starvation. Per-message outcomes
inside a batch preserve idempotent conflicts without failing unrelated
messages.

The final 30-second pinned screen at runtime revision `6b37ca8` accepted all
30,000 offered messages at 998.399 messages/s with zero saturation or errors.
Client p50/p95/p99 latency was 7.075/10.514/15.787 ms. Service CPU time was
16.366 seconds and peak RSS was 3,739,648 bytes. Relative to the original
screen, completed throughput increased 129.4%, service CPU time per accepted
message fell about 50.5%, and peak RSS fell about 27.7%.

Revision `6c71169` adds startup validation that PostgreSQL pool capacity is at
least two connections so one can be reserved for durable progress. A first
30-minute run then exposed a fixed-window rate-limit artifact: although the
load was paced at 1,000/s below the configured 1,200/s limit, delayed requests
could cluster in one wall-clock bucket and receive false HTTP 429 responses.
Revision `23ec945` replaces that policy with a bounded integer token bucket.
It preserves the configured sustained rate and per-key memory bound while
carrying unused capacity across clock boundaries. The qualification generator
also uses a bounded 4,096-request queue so temporary client-side HTTP/2
queueing cannot silently discard a scheduled offer; service admission remains
bounded at 256 in-flight messages.

The first final-head 30-minute attempt was then invalidated by the measurement
harness itself. Every 30 seconds, its progress monitor scanned the complete
messages table and computed `COUNT(DISTINCT sequence)`. At 1,789,583 rows the
messages relation occupied 1,558,126,592 bytes, and PostgreSQL reported 39
temporary files totaling 426,500,096 bytes. The resulting cache displacement
and storage queueing produced 1.30-second p95 and 3.59-second p99 latency. The
checkpoint log does not support checkpoint sync as the cause: sync phases were
4–159 ms while writes were deliberately spread over the configured 269-second
completion interval. The monitor now reads `conversations.next_sequence` and
checks only the last message and event through their primary keys. Exact full
counts and sequence reconciliation run once after load generation stops.

The first two-conversation mixed arm exposed a separate durable-write
bottleneck. One bounded admission slice was grouped by conversation, but the
reserved writer committed the largest conversation first and waited before
committing the second. The arm completed only 1,796,753 of 1,800,000 offers,
with 3,247 client saturation losses and approximately 3.15-second p95 latency.
Its 335,757 conversation batches accumulated 108,246 seconds of request-side
insert wait, and PostgreSQL CPU was about 49% above the one-conversation arm.

Revision `1154199` retains the same 16-message/2-millisecond admission bound
but commits all conversation-local groups from one slice in one outer
PostgreSQL transaction. Groups acquire sequence locks in deterministic order,
and each has its own savepoint, so an invalid group rolls back without
discarding successful independent groups. This pays one durable commit per
slice without growing the queue or copying message payloads again. Revision
`9fc1fc6` corrects the real-PostgreSQL fixture to use distinct workflow
identities; it does not change the runtime binary. The real database test
proves two valid groups commit with independent contiguous sequences while a
missing-conversation group fails in isolation.

Revisions `f37f4ad`, `195c323` and `29a0f19` replace those sequential
conversation-local savepoints with one canonically locked, set-based statement
across every conversation in a bounded admission slice. Exact retry lookup is
driven from the bounded input rather than the growing messages table, and
Rust-side deduplication plus compact inserted-row results avoid returning or
copying payload bytes that the worker already owns. Revision `c18f213` also
stops normal successful HAProxy requests from generating one journal record
per message while preserving warnings and errors.

The resulting `c18f213` 30-minute mixed arm completed and reconciled every
message. It reduced service, proxy and database CPU work from 1.435 to 1.207
ms per accepted message, a 15.9% improvement over `9fc1fc6`, and reduced the
maximum transport p95 from about 3.68 seconds to 356.654 ms. The remaining CPU
work was still 9.04% above the 1.107-ms weighted isolated-interface reference,
outside the unchanged 5% gate. PostgreSQL statistics identified 13 insert-only
autovacuums and 18 autoanalyzes on each 1.8-million-row append-only hot table.

Two retained maintenance experiments did not pass. Revision `851fe4d` moved
insert vacuum and analyze to a 100,000-row plus 1.0-scale geometric schedule;
its HTTPS arm lost 711 offers and combined CPU remained about 1.194 ms per
accepted message. Revision `7b73f6d` used fixed 250,000-row quanta; its HTTPS
arm lost 1,366 offers and combined CPU was about 1.202 ms per accepted message.
Both policies still forced repeated full-relation vacuum work despite the two
hot tables having no dead tuples, so revision `0dda2bf` removed them.

A paired five-minute A/B then isolated admission density. With otherwise
identical binaries and workloads, increasing the bounded linger from 2 to 8 ms
reduced conversation groups from 99,009 to 47,500 for 300,000 messages and
reduced combined service, proxy and PostgreSQL CPU from 1.213 to 1.085 ms per
message. Both arms reconciled exactly with bounded memory. Revision `4c5189b`
therefore adopted the 8-ms default while retaining the 16-message cap. Its
30-minute run met the CPU gate at 1.085 ms per accepted message, but 12
insert-triggered autovacuums on each append-only table produced late read
bursts and 1,446 HTTPS client-saturation losses.

Revision `5d84003` disables only insert-triggered vacuum on `messages` and
`conversation_events`. Ordinary dead-tuple autovacuum remains active for
retention deletes, automatic analyze remains active for planner statistics,
and PostgreSQL transaction-ID freeze safeguards are unchanged. The exact
indexed admission queries do not require visibility-map scans of insert-only
history. The final 30-minute arm performed zero autovacuums on both hot tables,
18 autoanalyzes on each, and ordinary autovacuum on the frequently updated
`conversations` table. It completed the full workload and passed the fixed
CPU, RSS, latency, completion and maintenance gates.

## Verification status

Formatting, strict all-target Clippy and all unit/service/OpenAPI/SQLite tests
pass at the final service revision. The public SDK revision passes its complete
Rust workspace suite (180 tests), Python 3.12 suite (58 tests), and TypeScript
typecheck, 66 tests and production build. The real-PostgreSQL suite, final
runtime smoke, long HTTPS/pinned/mixed traffic arms, three final 10,000-client
SSE arms, rotation phases and backup/restore checks have completed. Their
results and retained failures are recorded below.

### Message-throughput qualification

| Interface/workload | Source | Offered | Accepted | Completed rate | Errors | p95 | Service CPU | Service peak RSS | Status |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Pinned TLS, 30 s screen | `6b37ca8` | 30,000 | 30,000 | 998.399/s | 0 | 10.514 ms | 16.366 s | 3,739,648 B | Pass |
| Pinned TLS, 30 min first attempt | `6b37ca8` | 1,800,000 | 1,796,109 | 997.814/s | 3,767 client saturation + 124 HTTP 429 | 30.822 ms | 948.955 s | 10,272,768 B | Fail |
| Pinned TLS, final-head smoke | `23ec945` | 30,000 | 30,000 | 998.532/s | 0 | 9.918 ms | 16.587 s | 9,412,608 B | Pass |
| Pinned TLS, intrusive-monitor attempt | `23ec945` | 1,800,000 | 1,789,583 | 992.345/s | 1,912 client saturation + 8,505 HTTP 429 | 1,297.869 ms | 919.787 s | 11,702,272 B | Invalid/fail, preserved |
| Pinned TLS, 30 min | `23ec945` | 1,800,000 | 1,800,000 | 999.973/s | 0 | 17.757 ms | 967.556 s | 6,287,360 B | Pass |
| Web-PKI HTTPS, 5 min discriminator | `23ec945` | 300,000 | 300,000 | 999.973/s | 0 | 11.983 ms | 153.099 s | 12,533,760 B | Pass |
| Web-PKI HTTPS, 30 min | `23ec945` | 1,800,000 | 1,800,000 | 999.993/s | 0 | 21.838 ms | 917.651 s service + 227.937 s proxy | 13,680,640 B service + 15,814,656 B proxy | Pass |
| Mixed pinned/HTTPS, 30 min | `23ec945` | 1,800,000 | 1,796,753 | 998.178/s | 3,247 client saturation | ~3,146 ms | 955.604 s service + 127.421 s proxy | 18,452,480 B service + 15,564,800 B proxy | Fail, preserved |
| Mixed pinned/HTTPS, 5 min discriminator | `9fc1fc6` | 300,000 | 300,000 | 999.972/s aggregate | 0 | 56.035 ms max | 167.979 s service + 22.866 s proxy | 16,687,104 B service + 15,388,672 B proxy | Pass |
| Mixed pinned/HTTPS, 30 min | `9fc1fc6` | 1,800,000 | 1,800,000 | 999.981/s aggregate | 0 | 3,675.336 ms max | 907.740 s service + 105.119 s proxy | 17,522,688 B service + 15,327,232 B proxy | Completion pass; latency/CPU fail |
| Mixed pinned/HTTPS, 30 min | `c18f213` | 1,800,000 | 1,800,000 | 999.983/s aggregate | 0 | 356.654 ms max | 952.913 s service + 158.874 s proxy | 12,718,080 B service + 44,380,160 B proxy | Completion pass; CPU remains 9.04% over isolated reference |
| Mixed pinned/HTTPS, geometric maintenance | `851fe4d` | 1,800,000 | 1,799,289 | 999.589/s aggregate | 711 client saturation | 24.250 ms max | 962.501 s service + 164.564 s proxy | 11,706,368 B service + 41,652,224 B proxy | Completion and CPU fail, preserved |
| Mixed pinned/HTTPS, fixed maintenance | `7b73f6d` | 1,800,000 | 1,798,634 | 999.190/s aggregate | 1,366 client saturation | 61.764 ms max | 962.135 s service + 164.283 s proxy | 8,146,944 B service + 43,114,496 B proxy | Completion and CPU fail, preserved |
| Mixed pinned/HTTPS, 8-ms batching | `4c5189b` | 1,800,000 | 1,798,554 | 999.180/s aggregate | 1,446 client saturation | 60.797 ms max | 898.163 s service + 151.425 s proxy | 22,036,480 B service + 41,881,600 B proxy | CPU pass; completion fail, preserved |
| Mixed pinned/HTTPS, final | `5d84003` | 1,800,000 | 1,800,000 | 999.983/s aggregate | 0 | 34.990 ms max | 902.221 s service + 153.609 s proxy | 21,999,616 B service + 41,660,416 B proxy | **Pass** |

The current Linux qualification host has two vCPUs, 939 MiB RAM, no swap and a
90-GiB gp3 volume provisioned at 3,000 IOPS and 125 MiB/s. The server and load
generator run on the same host, so service CPU and generator CPU are captured
separately. Each isolated arm uses a fresh PostgreSQL 16 database.
The unprivileged test service listens on `127.0.0.1:8443` for pinned TLS and
the Web-PKI proxy listens on `conversation.i.qip.sh:9443`, with that hostname
mapped locally to `127.0.0.1` after public test DNS became unavailable. Nginx
served the earlier isolated message-throughput arms. HAProxy's HTTP/2 backend
served the final mixed-message and SSE arms. Production defaults remain port
443 for both public interfaces.

### SSE, security and recovery qualification

| Check | Status | Evidence |
| --- | --- | --- |
| 10,000 pinned SSE clients, 600 s, with 100 active streams | Pass | 10,000/10,000 connected and held; 300,000/300,000 active deliveries; zero failures, early exits or resyncs; service peak RSS 54.6 MB; event-loop lag 4.802 ms |
| 10,000 Web-PKI SSE clients, 600 s, with 100 active streams | Pass with HTTP/2 backend proxy | 10,000/10,000 connected and held; 300,000/300,000 active deliveries; zero failures, early exits or resyncs; service/proxy peak RSS 60.4/96.2 MB; event-loop lag 3.297 ms |
| 10,000 mixed pinned/Web-PKI SSE clients, 600 s, with 100 active streams | Pass | 5,000/5,000 per transport connected and held; 150,000/150,000 active deliveries; zero failures, early exits or resyncs; service/proxy peak RSS 58.0/64.2 MB; event-loop lag 2.995 ms |
| Cross-interface session and ordered-message continuity | Pass | Service integration suite |
| SDK pinned certificate, removed/future/expired pins and terminal security failures | Pass | Rust, Node and Python suites |
| Old-only, overlap, new-active and old-removed rotation | Pass | Cross-language suites plus live CLI old-active overlap, new-active overlap, new-only and old-pin rejection |
| Web-PKI HTTPS success and invalid certificate/hostname rejection | Pass | 1,800,000/1,800,000 HTTPS messages; self-signed endpoint rejected before challenge creation |
| PostgreSQL backup/restore with API verification | Pass | Restored 1,800,000 messages; encrypted read, idempotent retry, SSE resume, revocation and retention all passed |

The valid pinned arm reconciled 1,800,000 messages and 1,800,000 durable
events with continuous sequences and no eligible maintenance debt. PostgreSQL
reported zero temp files, deadlocks or rollbacks. Database CPU work was
approximately 0.521 ms per accepted message; service plus database CPU work
was approximately 1.058 ms per accepted message. PostgreSQL ended at
500,305,920 bytes RSS with a 564,629,504-byte high-water. Disk samples stayed
below 1,283 read IOPS, 258 write IOPS, 21.83 MiB/s reads, 11.04 MiB/s writes
and 43.48% utilization on the declared 3,000-IOPS/125-MiB/s gp3 volume. No
swap occurred.

The valid HTTPS arm also reconciled 1,800,000 messages and 1,800,000 durable
events with continuous sequences and no eligible maintenance debt. PostgreSQL
reported zero temporary files, deadlocks or rollbacks, and no swap occurred.
After subtracting its recorded start counter, PostgreSQL used 934.850 CPU
seconds. The service, proxy and PostgreSQL used approximately 0.510, 0.127 and
0.519 ms per accepted message respectively, or 1.156 ms combined. That is a
9.2% CPU-work premium over the 1.058 ms direct pinned path, attributable to the
additional Web-PKI reverse-proxy hop. Combined service, proxy and PostgreSQL
peak RSS was 586,203,136 bytes, 2.7% above the pinned service-plus-PostgreSQL
peak, and plateaued rather than growing. Disk samples remained below 1,727
read IOPS, 244 write IOPS, 13.50 MiB/s reads, 10.92 MiB/s writes and 52.23%
utilization.

The final corrected mixed arm reconciled all 1,800,000 messages and events,
split exactly 900,000 per conversation, with continuous sequences, zero
client saturation, zero request errors, zero eligible maintenance debt, zero
temporary files and zero deadlocks. It therefore proves that the grouped
storage correction removed the earlier transaction-completion failure. It is
not a production-capacity pass: pinned/HTTPS p95 latency was 3,669/3,675 ms.
After subtracting the recorded PostgreSQL start counter, service, proxy and
database CPU totaled about 2,583.0 seconds, or 1.435 ms per accepted message.
That is about 29.6% above the 1.107 ms weighted isolated-interface reference.
The load generator consumed another 540.0 CPU seconds on the same two-CPU
host, leaving little scheduler headroom. Service, proxy and PostgreSQL peak
RSS totaled about 589.9 MB and remained bounded. The database reached 2.53 GB;
storage utilization was modest and PostgreSQL reported no temporary-file or
lock-wait failure, so the remaining full-duration latency is a CPU/scheduling
capacity problem on this colocated two-CPU topology rather than a completion,
memory or gp3-throughput failure.

The subsequent `c18f213` mixed arm again reconciled 1,800,000 messages and
events, exactly 900,000 per conversation, with contiguous sequences, zero
client saturation, zero request errors, zero eligible maintenance debt, zero
temporary files, zero deadlocks and no swap. Pinned/HTTPS p95 latency was
194.535/356.654 ms. Service, proxy and PostgreSQL used 952.913, 158.874 and
1,061.177 CPU seconds respectively after subtracting the recorded database
start counter, or 1.207 ms per accepted message. The service, proxy and
PostgreSQL peaks were approximately 12.1, 42.3 and 507.5 MiB. Normal proxy
logging produced only seven journal lines. This was the strongest completed
mixed result before the final admission-density and maintenance corrections,
but its 9.04% CPU premium over the weighted isolated reference exceeded the
fixed 5% gate.

The final `5d84003` mixed arm reconciled exactly 1,800,000 messages and
1,800,000 events, split 900,000 per interface, with contiguous sequences, zero
client saturation, zero request errors, zero retry inserts, zero eligible
maintenance debt, zero temporary files, zero rollbacks and zero deadlocks.
Pinned and HTTPS p95 latency was 34.453 and 34.990 ms; p99 was 252.517 and
352.265 ms. Maximum event-loop lag was 6.716 ms. After subtracting the recorded
PostgreSQL start counter, service, proxy and PostgreSQL used 902.221, 153.609
and 877.197 CPU seconds. Their 1,933.027-second total is 1.073904 ms per
accepted message: 7.62% below the fixed 1.16247-ms gate, 3.00% below the
1.107116-ms weighted isolated reference and 11.04% below `c18f213`.

Service, proxy and PostgreSQL high-water RSS was 21,999,616, 41,660,416 and
441,507,840 bytes. Their conservative sum is 505,167,872 bytes, 3.40% below
the immediately preceding `4c5189b` run and 14.27% below `c18f213`. The service
ended at 5,800 KiB anonymous PSS and 11,571 KiB file PSS. The larger service
high-water than the older warm-cache `c18f213` observation is executable-page
charging on a cold artifact, not retained heap growth: the exact paired
`4c5189b` artifact had a slightly higher 22,036,480-byte service peak and
5,900-KiB anonymous PSS. No swap was configured or used.

PostgreSQL recorded zero insert-triggered autovacuums on `messages` and
`conversation_events`, while running 18 autoanalyzes on each. It continued to
vacuum the updated `conversations` table normally. Both hot relations ended
with zero dead tuples, the configured `autovacuum_vacuum_insert_threshold=-1`
was present on both, and no eligible retention work accumulated. This is the
expected separation between unnecessary insert-only scans and required
dead-tuple/freeze maintenance.

The 515,892,654-byte compressed backup had SHA-256
`3b55945e003ccefb52c2412b490e0a19dc805b3862d9ac5fe2360433cf42f858`.
After restore, an existing encrypted message was readable, a new message and
its idempotent retry both resolved to sequence 1,800,001, SSE resumed at that
sequence, and revocation immediately returned HTTP 401. With the bounded
short-retention verification settings, maintenance removed the revoked
delegation and its sessions and challenges while retaining exactly 1,800,001
messages and events.

Live rotation passed with the old certificate active under old+new pins, the
new certificate active under new+old pins, and the new certificate under the
new-only profile. An old-only client then failed at TLS pin verification and
the durable message count did not change. Invalid Web-PKI, wrong-service,
removed-pin, future-pin, expired-pin, TLS 1.2 and plaintext probes all failed;
challenge and message counts were unchanged.

Connection churn passed at the final runtime revision: 1,000/1,000 direct
pinned connections completed in 1.336 seconds and 1,000/1,000 Web-PKI
connections completed in 3.730 seconds, with zero failures, handshake
timeouts or connection-capacity rejections. A resumed TLS 1.3 probe reported
that early data was not sent, and the durable challenge count remained zero.

Each final SSE arm used 9,900 idle streams on one conversation and 100 active
streams on a second conversation. A bounded 10-message/s driver admitted 3,000
messages during the hold, so exact fan-out required 300,000 message events.
Pinned and Web-PKI each delivered 300,000/300,000; the mixed arm delivered
150,000 through each transport. Every one of the 30,000 requested streams
across the three independent arms connected and held to its deadline. There
were no connection failures, early exits, stream errors, resync events,
authorization-close events, capacity rejections or swap use. All three fresh
databases reconciled 3,000 messages and 3,000 events with continuous heads and
no eligible maintenance debt.

Qualification setup failures remain in the evidence bundle. The first active
pinned arm started its load as soon as capacity permits were visible, before
the handlers completed replay/subscription registration, so every active
client missed the first message; a fixed two-second registration interval
made the exact rerun pass. The first Web-PKI attempts proved that an Nginx
HTTP/1.1 upstream was unsuitable for 10,000 SSE streams on this host, then
proved the harness needed the private listener's 100-stream limit rather than
the direct listener's 128-stream limit. Finally, two synchronized 500/s mixed
ramps briefly exhausted the bounded replay semaphore. A predeclared 499/s and
501/s dephasing preserved exactly 1,000 opens/s and passed without increasing
any service limit.

The Nginx Web-PKI example passes `nginx -t` with Nginx 1.26.3. It was used for
the earlier isolated message-throughput arms with one bounded 256-connection
upstream keepalive pool, TLS 1.3 and HTTP/2, and buffering disabled only for
SSE.

That Nginx path passed those message-throughput arms but is not the recommended
10,000-SSE topology on a sub-1-GiB host: Nginx proxies each SSE request to the
private listener over a separate HTTP/1.1 backend socket. It exhausted its
4,096-worker-connection setting at about 4,061 streams; after the connection
limit was corrected, its 128-MiB cgroup was OOM-killed and service connection
state had already exceeded 300 MB. The final Web-PKI SSE arm instead uses the
checked-in HAProxy example with TLS 1.3/HTTP/2 downstream and cleartext HTTP/2
to the loopback service. The same 10,000 streams then held with proxy and
service peaks of 96.2 MB and 60.4 MB. The qualification harness uses the lower
common pool bound of 100 streams because the direct listener advertises 128
while the private Axum HTTP/2 listener advertises 100.

## Qualification boundary

The dual-transport implementation, cross-language clients, security matrix,
rotation, recovery, churn and 10,000-SSE gates are complete. On the declared
two-CPU tester, each isolated 1,000-message/s transport arm passes, all three
10,000-client SSE arms pass, and the final 1,000-message/s mixed arm passes the
fixed completion, correctness, CPU, RSS, latency and maintenance gates. The
dual-transport implementation is therefore **qualified on the declared test
topology**. The failed geometric, fixed-quantum and pre-fix runs remain in the
evidence bundle and are not omitted from the decision.

The largest remaining measured cost is the ordinary PostgreSQL durable-write
path, but it no longer prevents the target workload or resource gates. The
final runtime uses 1.073904 ms of service, proxy and database CPU per accepted
message with bounded queues and residency. The 8-ms linger remains bounded by
the unchanged 16-message batch cap and trades a small admission delay for fewer
durable commits; it is part of the qualified runtime and must be held fixed in
future comparisons.

The test Web-PKI arm uses a current public test wildcard certificate and local
DNS loopback so it exercises normal platform trust stores and the reverse
proxy path. It is not evidence of possession of a future production provider
domain. Mock-chain authorization is used to hold chain state stable during
capacity measurement. Production release qualification remains pending unless
all rows above pass on the declared production topology with a production
certificate, production chain projection and the retained evidence bundle.
That deployment check does not change the passing implementation-capacity
decision above.

The durable campaign archive stores the final non-secret evidence under
`evidence/mixed-1800s-5d84003-final` and the Linux artifacts under `artifacts`.
The repository records their hashes in
`docs/DUAL_TRANSPORT_FINAL_EVIDENCE_SHA256SUMS_2026_10_04.txt`. The archive
includes exact load receipts, database reconciliation, table maintenance
counters, relation options, service memory breakdown, CPU/RSS monitors, I/O
samples and retained logs.
