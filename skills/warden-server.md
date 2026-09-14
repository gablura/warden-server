---
name: warden-backend
description: The authoritative backend pattern for Warden — the eight-layer module structure, concurrency-safe spend evaluation, the fail-closed error doctrine, webhook idempotency, the settlement-adapter boundary, and Redis/security/deployment conventions. Use this whenever writing, editing, or reviewing any Warden backend code — a route, controller, service, query/mutation function, a new module, a Prisma schema change, a webhook handler, or anything touching the policy engine, credentials, or audit log. This governs correctness in a codebase where a bug means real money moves incorrectly, not just a wrong UI state — treat every rule here as load-bearing, not stylistic.
---

# Warden Backend

## What this codebase actually is

This is a financial control plane. Every module here either decides whether an AI agent is allowed to spend money, or records that it did. That framing changes what "good code" means relative to a typical CRUD backend: a swallowed error, a race condition, or a mutable audit row aren't code-quality nitpicks here — they're the exact failure modes that cost someone real money or destroy the audit trail a customer is paying for. Hold this codebase to that standard, not a generic Express-app standard.

---

## 1. The eight-layer module pattern — non-negotiable shape

Every module (`identity`, `policy`, `ingestion`, `approvals`, `settlement`, `audit`, `alerts`) follows this exact layering. Omit a file only if the module genuinely has nothing for that layer (e.g., a read-only module skipping `mutation.ts`) — never collapse two layers together for convenience.

```
modules/policy/
├── policy.routes.ts        # HTTP wiring only — no logic
├── policy.controller.ts    # parses request, calls service, shapes response — no business logic
├── policy.service.ts       # orchestration, business rules — the only layer allowed to call multiple other layers
├── policy.query.ts         # read-only Prisma calls — the only file allowed to import PrismaClient for reads
├── policy.mutation.ts      # write Prisma calls — the only file allowed to import PrismaClient for writes
├── policy.access.ts        # authorization checks — isolated so permission logic is auditable in one place
├── policy.validators.ts    # Zod schemas — validated once, at the controller boundary, never re-validated downstream
└── policy.selects.ts       # Prisma select shapes — defined once per entity, reused everywhere that entity is queried
```

Worked example, all eight layers, real code:

```ts
// policy.selects.ts — one shape per entity, never redefined inline in a query
export const policyWithAllowlistSelect = {
  id: true, orgId: true, version: true,
  maxPerTransaction: true, maxPerDay: true,
  merchantAllowlist: true, requireApprovalAbove: true,
  updatedBy: true, createdAt: true,
} satisfies Prisma.PolicySelect;
```

```ts
// policy.validators.ts — Zod at the boundary, nowhere else
export const createPolicySchema = z.object({
  maxPerTransaction: z.coerce.number().positive(),
  maxPerDay: z.coerce.number().positive(),
  requireApprovalAbove: z.coerce.number().nonnegative(),
  merchantAllowlist: z.array(z.string().min(1)).min(1),
}).refine(d => d.maxPerTransaction <= d.maxPerDay,
  { message: 'Per-transaction limit cannot exceed the daily limit' });

export type CreatePolicyInput = z.infer<typeof createPolicySchema>;
```

```ts
// policy.access.ts — authorization is its own layer, never inlined in a controller
export async function assertCanEditPolicy(userId: string, orgId: string) {
  const membership = await prisma.orgMembership.findUnique({
    where: { userId_orgId: { userId, orgId } }, select: { role: true },
  });
  if (!membership || membership.role === 'VIEWER') {
    throw new ForbiddenError('Insufficient permissions to edit policy');
  }
}
```

```ts
// policy.mutation.ts — policies are append-only versions, never edited in place.
// Why: an in-place edit could change the rule out from under a transaction
// already mid-evaluation, and it destroys "what limit was in effect when
// this was approved" as an answerable question forever.
export async function mutateCreatePolicyVersion(orgId: string, input: CreatePolicyInput, updatedBy: string) {
  const latest = await prisma.policy.findFirst({ where: { orgId }, orderBy: { version: 'desc' } });
  return prisma.policy.create({
    data: { ...input, orgId, updatedBy, version: (latest?.version ?? 0) + 1 },
    select: policyWithAllowlistSelect,
  });
}
```

```ts
// policy.service.ts — orchestration; the only layer that touches more than one concern
export async function servicePublishPolicy(userId: string, orgId: string, input: CreatePolicyInput) {
  await assertCanEditPolicy(userId, orgId);
  const policy = await mutateCreatePolicyVersion(orgId, input, userId);
  await invalidatePolicyCache(orgId);
  await writeAuditEntry({ entityType: 'Policy', entityId: policy.id, action: 'PUBLISH', actor: userId });
  return policy;
}
```

```ts
// policy.controller.ts — thin. If a controller has an `if` that isn't
// about HTTP status codes, that logic belongs in the service instead.
export async function publishPolicyHandler(req: Request, res: Response) {
  const input = createPolicySchema.parse(req.body);
  const policy = await servicePublishPolicy(req.user.id, req.params.orgId, input);
  res.status(201).json({ success: true, data: policy });
}
```

```ts
// policy.routes.ts — wiring only
router.post('/orgs/:orgId/policies', requireAuth, publishPolicyHandler);
```

---

## 2. Prisma schema conventions

- **`Decimal(18, 6)` for every monetary field. Never `Float`.** Float rounding error is cosmetic in most apps and a real defect here.
- **Every `Transaction` row stores `policyVersionId`.** "What rule was in effect when this was approved" must be answerable forever — see the versioning rationale in §1.
- **`AuditLog` is append-only at the database grant level**, not just by convention — revoke `UPDATE`/`DELETE` on that table for the application's DB role. Application-layer discipline alone is not enough for a table customers will use as evidence.
- **Index for the access patterns that actually happen:** `Transaction` on `(agentId, createdAt)` and `(status)`; `AuditLog` on `(entityType, entityId)`. Both tables grow unbounded by design — a missing index here degrades silently until it's a production incident, not a slow dev-environment query.
- **One row per `(agentId, day)` in a dedicated `SpendCounter` table** — this is what makes concurrency-safe spend checks possible at all; see §3.

---

## 3. Concurrency safety — the single most important pattern in this codebase

Two transactions from the same agent arriving milliseconds apart can both read "today's spend" before either writes it back, both pass a limit check that should only have let one through, and the agent ends up over its limit. This is a TOCTOU bug, and here it means money moving that shouldn't have.

```ts
// modules/policy/policy.service.ts
export async function evaluateAndReserveSpend(
  agentId: string, amount: Decimal, merchant: string
): Promise<Decision> {
  return prisma.$transaction(async (tx) => {
    const agent = await tx.agent.findUniqueOrThrow({ where: { id: agentId } });
    const policy = await getPolicyCached(agent.policyId);

    // Row-level lock — any concurrent call for this same agent blocks
    // here until this transaction commits. This is the fix.
    const [counter] = await tx.$queryRaw<{ used_today: Decimal }[]>`
      SELECT used_today FROM "SpendCounter"
      WHERE "agentId" = ${agentId} AND day = CURRENT_DATE FOR UPDATE
    `;
    const usedToday = counter?.used_today ?? new Decimal(0);
    const projected = usedToday.plus(amount);

    // Fail-closed: this function returns a Decision and never throws
    // past this point, so a forgotten case cannot silently become "allowed."
    if (amount.gt(policy.maxPerTransaction)) return { decision: 'DENY', reason: 'PER_TX_LIMIT_EXCEEDED' } as const;
    if (projected.gt(policy.maxPerDay))       return { decision: 'DENY', reason: 'DAILY_LIMIT_EXCEEDED' } as const;
    if (!policy.merchantAllowlist.includes(merchant))
      return { decision: 'DENY', reason: 'MERCHANT_NOT_ALLOWED' } as const;

    // Reserve atomically, still inside the same lock
    await tx.$executeRaw`
      INSERT INTO "SpendCounter" ("agentId", day, "usedToday")
      VALUES (${agentId}, CURRENT_DATE, ${amount})
      ON CONFLICT ("agentId", day) DO UPDATE SET "usedToday" = "SpendCounter"."usedToday" + ${amount}
    `;

    return amount.gt(policy.requireApprovalAbove)
      ? ({ decision: 'REQUIRES_APPROVAL' } as const)
      : ({ decision: 'APPROVE' } as const);
  });
}
```

If a pending-approved transaction later times out and auto-denies, decrement this same counter inside the same lock — it must reflect actual settled + pending-approved spend, never "everything ever attempted." Any new code path that changes an agent's effective daily spend goes through this locked counter — there is no second way to do this correctly.

---

## 4. Error handling — the fail-closed doctrine

```ts
// lib/appError.ts
export abstract class AppError extends Error {
  abstract readonly statusCode: number;
  abstract readonly code: string;
}
export class ForbiddenError extends AppError { statusCode = 403; code = 'FORBIDDEN'; }
export class UnauthorizedError extends AppError { statusCode = 401; code = 'UNAUTHORIZED'; }
export class ValidationError extends AppError { statusCode = 422; code = 'VALIDATION_ERROR'; }
export class NotFoundError extends AppError { statusCode = 404; code = 'NOT_FOUND'; }
```

**The rule, stated precisely:** in `policy/`, `settlement/`, and `ingestion/`, there is no `catch` block that swallows an error — every catch either re-throws, or explicitly returns a typed `Decision`/result that resolves to the safe outcome (`DENY`, not settled, not approved). A bare `catch {}` or a `return` where a `throw` was intended in these three modules is not a style issue — it's the exact bug class that turns an error into a silent "allow."

```ts
// middleware/errorHandler.ts — the only place that catches broadly, for everything else
export function errorHandler(err: unknown, req: Request, res: Response, next: NextFunction) {
  if (err instanceof AppError) {
    return res.status(err.statusCode).json({ success: false, code: err.code, message: err.message });
  }
  logger.error({ err, correlationId: req.correlationId }, 'Unhandled error');
  res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'Something went wrong' });
}
```

---

## 5. Webhook ingestion & idempotency

```ts
export async function handleSettlementWebhook(req: Request, res: Response) {
  const signature = req.headers['x-signature'] as string;
  const provider = resolveProvider(req.params.rail);

  // Verify against the raw body, not parsed JSON — signatures are over exact bytes
  if (!provider.verifyWebhookSignature(req.rawBody, signature)) {
    throw new UnauthorizedError('Invalid webhook signature');
  }

  const idempotencyKey = req.headers['x-idempotency-key'] as string;
  const isFirstDelivery = await redis.set(`webhook:${idempotencyKey}`, '1', 'EX', 86400, 'NX');
  if (!isFirstDelivery) {
    // Expected shape of a retried delivery, not an error. 200 so the
    // sender stops retrying; no further processing.
    return res.status(200).json({ success: true, deduplicated: true });
  }

  await serviceProcessSettlementEvent(req.body);
  res.status(200).json({ success: true });
}
```

The `NX` flag is what makes this atomic — two concurrent deliveries race to set the same key, exactly one wins. Every webhook handler in `ingestion/` follows this exact shape; there is no webhook endpoint that skips the idempotency check because "this provider probably won't double-deliver."

---

## 6. The settlement adapter boundary

```ts
export interface SettlementProvider {
  createWallet(orgId: string, chain: string, asset: string): Promise<Wallet>;
  getBalance(walletId: string): Promise<{ amount: Decimal; asset: string }>;
  initiateTransfer(walletId: string, tx: PendingTransaction): Promise<SettlementResult>;
  verifyWebhookSignature(rawBody: Buffer, signature: string): boolean;
}
```

**The one rule that matters:** no module outside `settlement/` ever imports a rail-specific type or class (`CircleWalletProvider`, an x402 payload shape, etc.) — `policy/`, `approvals/`, and `audit/` see only `Transaction` and `SettlementResult`. Also: `initiateTransfer` returns `PENDING_CONFIRMATION`, never `SETTLED`, directly — finality is only ever set by a verified confirmation webhook. Marking something settled optimistically on the initiate call is a data-integrity bug with financial consequences.

*Adding a new rail (a second or third `SettlementProvider` implementation) is a recurring, higher-detail task with its own checklist — that belongs in a dedicated adapter-specific skill once you're building against a second rail. This section covers the boundary every module must respect; it isn't the full playbook for implementing one.*

---

## 7. Redis usage

| Use | Pattern | Why it has to be Redis |
|---|---|---|
| Credential revocation | `SADD`/`SISMEMBER` on `revoked-credentials` | Sub-millisecond check on every request |
| Policy cache | `GET`/`SET` on `policy:{orgId}`, invalidated on publish | Read on every transaction, written rarely |
| Rate limiting | Sliding window per credential | Needs atomic increment-and-check |
| Webhook idempotency | `SET NX EX` | Atomicity is the entire point — §5 |
| SSE fan-out | Pub/Sub, one channel per org | Any API instance can publish/receive without sticky sessions |
| Approval timeouts | BullMQ (Redis-backed) delayed jobs | Survives a server restart; `setTimeout` does not |

---

## 8. Security middleware — required on every request

```ts
app.use(helmet());
app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));
app.use(correlationIdMiddleware);   // req.correlationId, logged on every line downstream
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));  // preserved for HMAC checks
app.use('/api', rateLimiter);       // per-org AND per-agent-credential — an agent is the threat model here
app.use('/api', requireAuth);
```

Rate limit per agent credential, not just per IP. CSRF protection applies to browser-facing dashboard mutations; machine-to-machine ingestion endpoints authenticate via HMAC instead and don't need it.

---

## 9. Deployment must-haves

- **A global "freeze all agent spend" kill switch, built from day one** — not a v2 feature. The ability to halt every pending and future transaction org-wide in one action, before the bug is diagnosed, is what turns an incident into a non-event.
- **Config validation at boot** — fail loudly and immediately if `CIRCLE_API_KEY`, `CIRCLE_WEBHOOK_SECRET`, `DATABASE_URL`, or `REDIS_URL` are missing. Never let a misconfigured deploy silently start accepting traffic it can't correctly process.
- **Graceful shutdown on `SIGTERM`** — stop accepting new requests, let in-flight policy evaluations and BullMQ jobs finish, then close connections. An abrupt kill mid-transaction reintroduces the exact ambiguous state §3 and §4 exist to prevent.
- **Migrations via `prisma migrate deploy` as an explicit CI/CD step** — never a hand-edited production schema.

---

## 10. Checklist — adding any new module

1. All eight layers present (§1), even if some are thin — never collapsed together.
2. Every entity has one `selects.ts` shape, reused everywhere it's queried.
3. Every write path is traced for a bare/swallowing `catch` — none exist in `policy/`, `settlement/`, `ingestion/`.
4. Every mutation that changes state the audit trail cares about calls `writeAuditEntry`.
5. Any counter or limit check that can race under concurrent calls uses the row-lock pattern from §3 — not a naive read-then-write.
6. Every webhook handler verifies signature against the raw body and checks idempotency before processing.
7. Every new Prisma model with a money field uses `Decimal`, never `Float`.

## 11. Non-negotiables

- ✅ Eight-layer module shape, every module, no exceptions
- ✅ Policies (and anything else "what rule applied when" matters for) are append-only versions
- ✅ Row-level locking on any concurrent spend/counter check
- ✅ Fail-closed: unhandled error in `policy/`/`settlement/`/`ingestion/` → deny, never allow
- ✅ Idempotency check before processing any webhook
- ✅ Rail-specific types stay inside `settlement/` — never leak upward
- ❌ Never `Float` for money
- ❌ Never an in-place `UPDATE` on `Policy` or `AuditLog` rows
- ❌ Never mark a transaction `SETTLED` before a confirmation webhook verifies it
- ❌ Never a webhook handler without signature verification + idempotency
- ❌ Never business logic in a controller or routes file