import { prisma } from "../db/client.js";
import { policyRegistryAbi } from "./abis/policyRegistry.js";
import { spendGuardAbi } from "./abis/spendGuard.js";
import { adminAddress, approverAddress } from "./client.js";
import { ChainUnavailableError } from "./errors.js";
import { serializeTx } from "./txQueue.js";
import { isCircleConfigured } from "../auth/wallet.js";
import { CircleError, executeContractAndWait } from "./circleExecution.js";
import { deploymentKey, type Deployment } from "./orgContracts.js";
import { recordTxFailure } from "./txAlert.js";

// ── Transaction signing router (§2 + §6) ─────────────────────────────
//
// Every gas-spending route submits through here. Two jobs: pick the right
// deployment (caller-resolved, per org/agent) and pick WHO signs:
//
// - Admin-only functions (setPolicy, setAllowlist, setApprover, setPaused):
//   the contracts accept ONLY the admin key, so these always go through the
//   admin relayer on the target deployment. Per-person identity is carried
//   by the scoped session + audit row, not msg.sender — the contract leaves
//   no other option without an access-control upgrade.
// - Approver functions (approvePending, rejectPending): signed by the acting
//   person's embedded wallet via Circle when possible, else the approver
//   relayer. Either way the audit row names the person, their wallet, and
//   which key actually signed (`via`).
//
// Circle vs relayer is decided BEFORE submission from local state
// (configured? wallet on record?) and never re-decided after — a Circle
// failure can therefore never double-submit through the relayer. Circle
// configured + wallet present but Circle errors → fail closed (503).
// Circle absent/unconfigured → relayer (degraded mode, same as today).

export type SigningResult = {
  txHash: string;
  /// The on-chain msg.sender.
  signer: string;
  via: "circle" | "relayer";
};

/// The caller's on-chain grant is missing (their wallet was never granted
/// approver, or was revoked). Thrown BEFORE any gas is spent so the route
/// can answer 403 instead of submitting a doomed transaction.
export class GrantMissingError extends Error {
  constructor(public readonly walletAddress: string) {
    super(`wallet ${walletAddress} has no on-chain approver grant — ask an admin to sync approvers`);
    this.name = "GrantMissingError";
  }
}

type ContractName = "spendGuard" | "policyRegistry";

function contractAddress(deployment: Deployment, contract: ContractName): `0x${string}` {
  return contract === "spendGuard" ? deployment.spendGuard : deployment.policyRegistry;
}

function contractAbi(contract: ContractName) {
  return contract === "spendGuard" ? spendGuardAbi : policyRegistryAbi;
}

/// Admin-only write through the admin relayer on the target deployment.
/// Serialized per chain so concurrent writes never collide on the nonce.
export async function submitAsAdmin(
  deployment: Deployment,
  contract: ContractName,
  functionName: string,
  args: unknown[],
): Promise<SigningResult> {
  const queue = `admin:${deployment.chainId}`;
  try {
    const txHash = await serializeTx(queue, () =>
      // Args are built at reviewed call sites against the matching ABI;
      // writeContract's strict tuple typing can't express dynamic dispatch,
      // hence the single contained cast.
      deployment.adminWalletClient.writeContract({
        address: contractAddress(deployment, contract),
        abi: contractAbi(contract),
        functionName,
        args,
      } as never),
    );
    return { txHash, signer: adminAddress, via: "relayer" };
  } catch (err) {
    if (err instanceof ChainUnavailableError) throw err;
    // A submission failure — as opposed to a route/validation failure — is
    // exactly what monitoring should surface (hardening review §5.2).
    recordTxFailure({ functionName, deployment: deploymentKey(deployment) });
    // Extract revert reason from viem error if available
    const revertReason = err instanceof Error
      ? (err as { shortMessage?: string; cause?: unknown }).shortMessage
        ?? (err.cause instanceof Error ? err.cause.message : undefined)
        ?? err.message
      : String(err);
    throw new ChainUnavailableError(`admin transaction ${functionName} failed: ${revertReason}`, { cause: err });
  }
}

/// Read SpendGuard.approvers for a wallet on the target deployment.
async function readGrant(deployment: Deployment, walletAddress: string): Promise<boolean> {
  try {
    return await deployment.publicClient.readContract({
      address: deployment.spendGuard,
      abi: spendGuardAbi,
      functionName: "approvers",
      args: [walletAddress as `0x${string}`],
    });
  } catch (err) {
    throw new ChainUnavailableError(`could not read on-chain approver state for ${walletAddress}`, { cause: err });
  }
}

/// Approver write (approvePending / rejectPending) signed by the acting
/// person: Circle execution from their embedded wallet when available,
/// approver relayer otherwise. Pre-checks the on-chain grant first so a
/// missing grant is a 403, never wasted gas.
export async function submitAsApprover(args: {
  operatorId: string;
  deployment: Deployment;
  functionName: "approvePending" | "rejectPending";
  functionSignature: string;
  requestArgs: [bigint];
  ensureUnresolved: () => Promise<void>;
}): Promise<SigningResult> {
  const { operatorId, deployment } = args;

  // Circle path needs the walletId (Circle addresses wallets by id, not by
  // hex). Looked up from the user row — service credentials have no user
  // row and always take the relayer path below.
  const user = await prisma.user.findUnique({ where: { id: operatorId } });
  const walletId = user?.walletId ?? null;
  const walletAddress = user?.walletAddress ?? null;

  const useCircle = isCircleConfigured() && !!walletId && !!walletAddress;

  if (useCircle) {
    const queue = `circle:${deployment.chainId}:${walletAddress}`;
    try {
      return await serializeTx(queue, async () => {
        if (!(await readGrant(deployment, walletAddress!))) {
          throw new GrantMissingError(walletAddress!);
        }
        await args.ensureUnresolved();
        const { txHash } = await executeContractAndWait({
          walletId: walletId!,
          contractAddress: deployment.spendGuard,
          abiFunctionSignature: args.functionSignature,
          abiParameters: args.requestArgs.map((v) => v.toString()),
          // Fresh UUID per attempt; repeats are safe because the contract
          // reverts already-resolved requests (mapped to 409 by callers).
        });
        return { txHash, signer: walletAddress!, via: "circle" as const };
      });
    } catch (err) {
      if (err instanceof GrantMissingError || err instanceof ChainUnavailableError) throw err;
      // The grant pre-check passed and a submission was attempted: a
      // failure here is a real submission failure — record it for the
      // burst monitor before wrapping (see chain/txAlert.ts).
      recordTxFailure({ functionName: args.functionName, deployment: deploymentKey(deployment) });
      if (err instanceof CircleError) {
        throw new ChainUnavailableError(`approval signing via Circle failed: ${err.message}`, { cause: err });
      }
      throw err;
    }
  }

  // Relayer fallback (Circle unconfigured or wallet not provisioned yet):
  // same serialized check-then-send discipline as before.
  const queue = `approver:${deployment.chainId}`;
  try {
    const txHash = await serializeTx(queue, async () => {
      await args.ensureUnresolved();
      return deployment.approverWalletClient.writeContract({
        address: deployment.spendGuard,
        abi: spendGuardAbi,
        functionName: args.functionName,
        args: args.requestArgs,
      });
    });
    return { txHash, signer: approverAddress, via: "relayer" };
  } catch (err) {
    if (err instanceof ChainUnavailableError) throw err;
    recordTxFailure({ functionName: args.functionName, deployment: deploymentKey(deployment) });
    const revertReason = err instanceof Error
      ? (err as { shortMessage?: string; cause?: unknown }).shortMessage
        ?? (err.cause instanceof Error ? err.cause.message : undefined)
        ?? err.message
      : String(err);
    throw new ChainUnavailableError(`approval transaction ${args.functionName} failed: ${revertReason}`, { cause: err });
  }
}

/// Submit a transaction as an agent using the agent's embedded wallet via Circle.
/// Mirrors submitAsApprover but uses the agent's wallet (from the agent table).
export async function submitAsAgent(args: {
  agentAddress: string;
  deployment: Deployment;
  functionName: "requestPayment";
  functionSignature: "requestPayment(address,address,uint256)";
  requestArgs: readonly [agent: `0x${string}`, counterparty: `0x${string}`, amount: bigint];
  ensureUnresolved: () => Promise<void>;
}): Promise<SigningResult> {
  const { agentAddress, deployment } = args;

  // Look up the agent's wallet info
  const agent = await prisma.agent.findUnique({ where: { address: agentAddress.toLowerCase() } });
  const walletId = agent?.circleWalletId ?? null;
  const walletAddress = agent?.address ?? null;

  const useCircle = isCircleConfigured() && !!walletId && !!walletAddress;

  if (useCircle) {
    const queue = `circle:${deployment.chainId}:${walletAddress}`;
    try {
      return await serializeTx(queue, async () => {
        if (!(await readGrant(deployment, walletAddress!))) {
          throw new GrantMissingError(walletAddress!);
        }
        await args.ensureUnresolved();
        const { txHash } = await executeContractAndWait({
          walletId: walletId!,
          contractAddress: deployment.spendGuard,
          abiFunctionSignature: args.functionSignature,
          abiParameters: args.requestArgs.map((v: [`0x${string}`, `0x${string}`, bigint][number]) => v.toString()),
        });
        return { txHash, signer: walletAddress!, via: "circle" as const };
      });
    } catch (err) {
      if (err instanceof GrantMissingError || err instanceof ChainUnavailableError) throw err;
      recordTxFailure({ functionName: args.functionName, deployment: deploymentKey(deployment) });
      if (err instanceof CircleError) {
        throw new ChainUnavailableError(`agent signing via Circle failed: ${err.message}`, { cause: err });
      }
      throw err;
    }
  }

  // Relayer fallback (Circle unconfigured or wallet not provisioned yet)
  const queue = `agent:${deployment.chainId}:${walletAddress}`;
  try {
    const txHash = await serializeTx(queue, async () => {
      await args.ensureUnresolved();
      return deployment.approverWalletClient.writeContract({
        address: deployment.spendGuard,
        abi: spendGuardAbi,
        functionName: "requestPayment" as const,
        args: args.requestArgs as readonly [`0x${string}`, `0x${string}`, bigint],
      });
    });
    return { txHash, signer: approverAddress, via: "relayer" };
  } catch (err) {
    if (err instanceof ChainUnavailableError) throw err;
    recordTxFailure({ functionName: args.functionName, deployment: deploymentKey(deployment) });
    const revertReason = err instanceof Error
      ? (err as { shortMessage?: string; cause?: unknown }).shortMessage
        ?? (err.cause instanceof Error ? err.cause.message : undefined)
        ?? err.message
      : String(err);
    throw new ChainUnavailableError(`agent transaction ${args.functionName} failed: ${revertReason}`, { cause: err });
  }
}
