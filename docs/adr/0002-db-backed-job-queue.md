# ADR-0002: Database-Backed Job Queue for Async Work

- Status: Accepted
- Date: 2026-02-11
- Decision owner: Platform runtime
- Supersedes: none

## Context

The initial implementation used Cloudflare Queues for async issuance and revocation jobs.
Institutional self-hosting requirements now require queue state and transport to run without the
Cloudflare Queue product.

Current platform constraints:

- Runtime remains Cloudflare Workers for hosted operation.
- Shared tenant data remains in D1.
- Immutable credential objects remain in R2.
- v1 architecture continues to prefer one clear path per capability.

## Decision

Use a D1-backed `job_queue_messages` table as the queue transport and source of truth for async
jobs. API endpoints enqueue messages into D1 directly. Cloudflare Queue bindings are removed from
the API runtime configuration.

## Rationale

- Removes dependency on vendor queue infrastructure.
- Keeps queue visibility and auditability inside the primary data store.
- Aligns with self-host deployment direction where database infrastructure is the baseline.
- Simplifies deployment topology by removing a dedicated queue product requirement.

## Consequences

- Queue lifecycle semantics (retry, dead-letter, leases) must be explicitly implemented in
  application logic and schema over time.
- Existing queue payload contracts remain useful and are stored as JSON in D1.
- SaaS configuration no longer needs queue producer/consumer bindings.

## Rollback Plan

If D1-backed queueing is not viable under load or reliability requirements:

1. Reintroduce an adapter interface for queue transport.
2. Add Cloudflare Queue transport behind that adapter without changing HTTP contracts.
3. Migrate pending D1 queue messages into the selected transport.
4. Keep idempotency-key behavior stable through the migration.

