# Warden Server

Fastify API server for the Warden governance and visibility layer for AI agent spending. This server provides the REST API and WebSocket connections for the Warden dashboard, serving data from PostgreSQL while maintaining a live connection to the Arc blockchain via chain event indexers.

## 🏗️ Architecture

### Data Flow
```
Agent Payment → Smart Contracts → Chain Events → Indexer → PostgreSQL → API/WebSocket → Dashboard
```

### Components
- **Fastify Server**: REST API and WebSocket hub
- **Chain Indexers**: Live event listeners for SpendGuard and PolicyRegistry contracts
- **Prisma ORM**: Database access with PostgreSQL
- **Viem Clients**: Blockchain interaction for Arc network
- **WebSocket**: Real-time updates to connected dashboard clients

### Technology Stack
- **Runtime**: Node.js with TypeScript
- **Server**: Fastify 5.0
- **Database**: PostgreSQL with Prisma 7
- **Blockchain**: Arc (Circle's EVM-compatible L1) via Viem
- **Validation**: Zod for schema validation

## 📋 Prerequisites

- Node.js 18+ 
- PostgreSQL 14+
- Arc blockchain RPC access
- Deployed Warden smart contracts

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm install
```

### 2. Set Up Environment Variables
Copy the example environment file and configure:
```bash
cp .env.example .env
```

Required environment variables:
```bash
# Server Configuration
PORT=4000
CORS_ORIGIN=http://localhost:3000

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/warden

# Arc Blockchain
ARC_RPC_URL=https://arc-testnet.circle.com
ARC_CHAIN_ID=5042002

# Deployed Contract Addresses
POLICY_REGISTRY_ADDRESS=0x...
SPEND_GUARD_ADDRESS=0x...
AUDIT_LOG_ADDRESS=0x...

# Wallet Keys (never commit these)
ADMIN_PRIVATE_KEY=0x...
APPROVER_PRIVATE_KEY=0x...
```

### 3. Set Up Database
```bash
# Run database migrations
npm run db:migrate

# (Optional) Open Prisma Studio for database management
npm run db:studio
```

### 4. Start the Server
```bash
# Development mode with hot reload
npm run dev

# Production build and start
npm run build
npm start
```

The server will start on `http://localhost:4000` by default.

## 🌐 API Endpoints

### Health Check
```http
GET /health
```
Returns server health status.

### Agents

Both routes read caps and spend live from `PolicyRegistry` on every request.
The `agents` rows are used only for dashboard metadata (label, status,
timestamps) and payment history, because the indexed spend counter is never
rolled over at the UTC day boundary and would report yesterday's total against
today's cap. If the chain can't be read the route answers
`503 { "error": "chain_unavailable" }` instead of falling back to stale values.

```http
GET /agents
```
Returns all agents ordered by current on-chain spend. Each entry carries the
live caps (`dailyCap`, `perTxCap`, `escalationThreshold`), `spentToday`,
`remainingToday`, the UTC `currentDay` the counter applies to, `policyExists`
(false when the registry has never seen the address), `policySource`, and the
`blockNumber` all of those were read at.

```http
GET /agents/:address
```
Returns agent details with recent payment history (last 50 transactions).
Addresses are matched case-insensitively.

### Policies (Admin)
```http
POST /policies
Content-Type: application/json

{
  "agent": "0x...",
  "dailyCap": "1000000000",
  "perTxCap": "100000000", 
  "escalationThreshold": "50000000"
}
```
Sets policy for an agent. Returns transaction hash.

```http
POST /policies/allowlist
Content-Type: application/json

{
  "agent": "0x...",
  "counterparty": "0x...",
  "allowed": true
}
```
Updates allowlist for an agent. Returns transaction hash.

### Approvals
```http
GET /approvals
```
Returns all pending approval requests.

```http
POST /approvals/:id/approve
```
Approves a pending payment request. Returns transaction hash.

```http
POST /approvals/:id/reject
```
Rejects a pending payment request. Returns transaction hash.

### Audit
```http
GET /audit?agent=0x...&from=2024-01-01&to=2024-12-31
```
Returns audit log events with optional filtering by agent and date range.

```http
GET /audit/export
```
Exports all audit events as CSV file for compliance.

### WebSocket
```http
WS /ws
```
Real-time updates for payment events and approval resolutions.

**Event Types:**
- `payment_approved` - New payment approved
- `payment_blocked` - Payment blocked with reason
- `payment_escalated` - Payment escalated for approval
- `approval_resolved` - Pending request approved/rejected
- `policy_set` - Agent policy updated
- `allowlist_updated` - Allowlist updated

## 🗄️ Database Schema

### Tables
- **agents**: Agent policies and spend tracking
- **events**: Payment decisions from SpendGuard
- **pending_requests**: Escalated payments awaiting approval
- **allowlist**: Agent counterparty permissions

### Key Features
- USDC amounts stored as BigInt (6 decimals) to avoid precision loss
- Daily spend tracking with automatic reset
- Indexed queries for performance

## 🔧 Development

### File Structure
```
src/
├── server.ts              # Fastify entry point
├── config.ts              # Environment configuration
├── chain/
│   └── client.ts         # Viem blockchain clients
├── db/
│   └── client.ts         # Prisma database client
├── indexer/
│   ├── watchPaymentEvents.ts    # SpendGuard event listener
│   └── watchPolicyEvents.ts     # PolicyRegistry event listener
├── ws/
│   └── broadcast.ts      # WebSocket event broadcasting
└── routes/
    ├── agents.ts         # Agent endpoints
    ├── policies.ts       # Policy management endpoints
    ├── approvals.ts      # Approval queue endpoints
    └── audit.ts          # Audit log endpoints
```

### Available Scripts
```bash
npm run dev          # Start development server with hot reload
npm run build        # Compile TypeScript to JavaScript
npm start            # Start production server
npm run db:migrate   # Run database migrations
npm run db:studio    # Open Prisma Studio
```

## 🧪 Testing

The server includes comprehensive error handling for the chain event indexers to ensure resilience:

- Individual event processing errors are logged but don't crash the indexer
- Server continues running even if indexers fail to start
- WebSocket broadcasts include error handling for disconnected clients

## 🔌 Chain Integration

### Indexers
The server runs two chain event indexers that:

1. **watchPaymentEvents**: Monitors SpendGuard for payment lifecycle events
   - Approvals, blocks, escalations
   - Pending request approvals/rejections
   - Updates database and broadcasts via WebSocket

2. **watchPolicyEvents**: Monitors PolicyRegistry for policy changes
   - Policy updates (caps, thresholds)
   - Allowlist modifications
   - Keeps agent data synchronized

### Blockchain Clients
- **Public Client**: Read-only access for event watching
- **Admin Wallet**: Policy management transactions
- **Approver Wallet**: Approval/rejection transactions

## 🔐 Security

### Current Status
- Per-person credentials with Clerk/scoped-token auth on all money-moving routes
- HMAC request signing (replay protection) — enforcement config-driven via
  `REQUIRE_SIGNED_REQUESTS` / `UNSIGNED_REQUESTS_ALLOWED_UNTIL`
- Rate limiting on all routes with tighter limits on gas-spending endpoints
- Private keys stored in environment variables
- CORS configured for frontend origin
- Input validation via Zod schemas

### Security Recommendations
1. Use secrets management for production deployments
2. Move server-held relayer keys to hardware/KMS-backed signers

## 🚢 Deployment

### Environment Setup
1. Set production environment variables
2. Configure production database
3. Deploy smart contracts to target Arc network
4. Update contract addresses in environment

### Production Start
```bash
npm run build
npm start
```

### Recommended Setup
- Use process manager (PM2, systemd)
- Configure reverse proxy (nginx)
- Enable SSL/TLS
- Set up monitoring and logging
- Configure database backups

## 📊 Monitoring

### Health Endpoints
- `/health` - Server health check
- Indexer status logged on startup and errors

### Logs
- Chain event processing errors logged with context
- Server startup logs include indexer status
- WebSocket connection status logged

## 🐛 Troubleshooting

### Database Connection Issues
```bash
# Check DATABASE_URL format
# Ensure PostgreSQL is running
# Verify network connectivity
```

### Chain Connection Issues
```bash
# Verify ARC_RPC_URL is accessible
# Check contract addresses are correct
# Ensure wallet has gas for transactions
```

### Indexer Not Starting
```bash
# Check environment variables are set
# Verify contract addresses are deployed
# Check RPC URL connectivity
# Review server logs for specific errors
```

### WebSocket Connection Issues
```bash
# Verify CORS_ORIGIN matches frontend
# Check firewall settings
# Review browser console for WebSocket errors
```

## 📝 Notes

### Known Limitations
- Spend records only at settlement time (not escalation time)
- Two large pending requests could both pass daily cap check before resolution
- Auth middleware needed for policy/approval routes
- Arc network values should be verified against official docs

### Performance Considerations
- Database queries are optimized with proper indexing
- Chain event processing is non-blocking
- WebSocket broadcasts are efficient for multiple clients
- BigInt serialization handles large USDC amounts safely

## 🔗 Related Projects

- **[warden-client](../warden-client)**: Next.js dashboard frontend
- **[warden-contracts](../contracts)**: Smart contracts for Arc blockchain

## 📄 License

MIT

## 🤝 Contributing

This is a governance and visibility layer for AI agent spending. Contributions should focus on security, reliability, and auditability.