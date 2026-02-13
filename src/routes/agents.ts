import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import { jwtVerify } from "jose";
import { getSupabaseClient } from "../lib/supabase";
import {
  ActiveAgentStatuses,
  AgentStatus,
  type AgentStatusValue,
  normalizeAgentStatus,
} from "../lib/agent-status";
import type { Bindings } from "../types/env";

const ONBOARDING_TIMEOUT_MS = 5 * 60 * 1000;
const STRATEGY_TIMEOUT_MS = 60 * 60 * 1000;
const DEPOSIT_TIMEOUT_MS = 60 * 60 * 1000;
const AGENT_NAME_MAX_LEN = 64;
const DEFAULT_MAX_AGENTS_PER_USER = 1;
const MAX_AGENTS_PER_USER_SETTING_KEY = "max_agents_per_user";
const AGENT_CREATION_TOKEN_MINT_SETTING_KEY = "agent_creation_token_mint";
const AGENT_CREATION_TOKEN_MIN_AMOUNT_SETTING_KEY =
  "agent_creation_token_min_amount";
const DEFAULT_SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com";
const ELIGIBILITY_EPSILON = 1e-9;

function statusTimeoutMs(status: AgentStatusValue) {
  if (
    status === AgentStatus.Starting ||
    status === AgentStatus.Onboarding ||
    status === AgentStatus.AwaitingRedirect
  ) {
    return ONBOARDING_TIMEOUT_MS;
  }
  if (status === AgentStatus.StrategyBuilding) {
    return STRATEGY_TIMEOUT_MS;
  }
  if (status === AgentStatus.AwaitingDeposit) {
    return DEPOSIT_TIMEOUT_MS;
  }
  return null;
}

function hasExpiredStatus(status: AgentStatusValue, timestamp?: string | null) {
  if (!timestamp) return false;
  const ttl = statusTimeoutMs(status);
  if (!ttl) return false;
  const elapsed = Date.now() - new Date(timestamp).getTime();
  return elapsed > ttl;
}

function parsePositiveInteger(value: unknown) {
  const parsed = Number.parseInt(String(value ?? "").trim(), 10);
  if (!Number.isFinite(parsed)) return null;
  if (parsed < 1) return null;
  return parsed;
}

function parseNonNegativeNumber(value: unknown) {
  const parsed = Number(String(value ?? "").trim());
  if (!Number.isFinite(parsed)) return null;
  if (parsed < 0) return null;
  return parsed;
}

function getCoreServiceToken(env: Bindings) {
  const token = String(env.CORE_SERVICE_TOKEN || env.CORE_API_TOKEN || "").trim();
  return token.length > 0 ? token : null;
}

function coreTokenAllowed(c: { env: Bindings; req: { header(name: string): string | undefined } }) {
  const expectedToken = getCoreServiceToken(c.env);
  if (!expectedToken) return false;
  const headerToken =
    c.req.header("x-core-token") ??
    c.req.header("authorization")?.replace(/^Bearer\s+/i, "");
  return Boolean(headerToken && headerToken === expectedToken);
}

function buildCoreHeaders(
  env: Bindings,
  options: { json?: boolean } = {}
) {
  const token = getCoreServiceToken(env);
  if (!token) return null;
  const headers: Record<string, string> = {
    "x-core-token": token,
  };
  if (options.json !== false) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
}

function normalizeProposedAgentName(value: unknown) {
  if (typeof value !== "string") return null;
  const compact = value.replace(/\s+/g, " ").trim();
  if (!compact) return null;
  // Keep the name English/ascii-friendly for consistent rendering/parsing.
  const ascii = compact.replace(/[^\x20-\x7E]/g, "");
  if (!ascii) return null;
  const cleaned = ascii.replace(/[^A-Za-z0-9 .,'&/+\-]/g, "").trim();
  if (!cleaned) return null;
  const startsOk = /^[A-Za-z0-9]/.test(cleaned);
  if (!startsOk) return null;
  if (cleaned.length < 3) return null;
  return cleaned.slice(0, AGENT_NAME_MAX_LEN);
}

function extractProposedAgentNameFromMessage(content: unknown) {
  if (typeof content !== "string") return null;
  if (!/\bDONE\b/.test(content)) return null;
  const directMatch =
    content.match(/(?:^|\|)\s*NAME\s*:\s*([^|\n\r]{2,120})/i) ??
    content.match(/(?:^|\|)\s*AGENT_NAME\s*:\s*([^|\n\r]{2,120})/i);
  if (directMatch?.[1]) {
    return normalizeProposedAgentName(directMatch[1]);
  }
  return null;
}

async function resolveProposedAgentName({
  env,
  agentId,
  userId,
}: {
  env: Bindings;
  agentId: string;
  userId: string;
}) {
  const supabase = getSupabaseClient(env);
  const { data, error } = await supabase
    .from("agent_messages")
    .select("role, content, created_at")
    .eq("agent_id", agentId)
    .eq("user_id", userId)
    .eq("role", "assistant")
    .order("created_at", { ascending: false })
    .limit(40);
  if (error) {
    console.warn("[agents] proposed name lookup failed", error);
    return null;
  }
  for (const message of data ?? []) {
    const extracted = extractProposedAgentNameFromMessage(message?.content);
    if (extracted) return extracted;
  }
  return null;
}

async function updateAgentName({
  env,
  id,
  userId,
  name,
}: {
  env: Bindings;
  id: string;
  userId: string;
  name: string;
}) {
  const normalized = normalizeProposedAgentName(name);
  if (!normalized) return;
  const supabase = getSupabaseClient(env);
  const now = new Date().toISOString();
  const { error } = await supabase
    .from("agents")
    .update({
      name: normalized,
      updated_at: now,
    })
    .eq("id", id)
    .eq("user_id", userId);
  if (error) {
    console.warn("[agents] name update failed", error);
  }
}

async function getMaxAgentsPerUserSetting(env: Bindings) {
  const supabase = getSupabaseClient(env);
  const { data, error } = await supabase
    .from("app_settings")
    .select("value_text")
    .eq("key", MAX_AGENTS_PER_USER_SETTING_KEY)
    .maybeSingle();
  if (error) {
    console.warn("[agents] failed to read app setting", error);
    return DEFAULT_MAX_AGENTS_PER_USER;
  }
  return (
    parsePositiveInteger(data?.value_text) ?? DEFAULT_MAX_AGENTS_PER_USER
  );
}

async function getAgentCreationTokenGateSettings(env: Bindings) {
  const supabase = getSupabaseClient(env);
  const { data, error } = await supabase
    .from("app_settings")
    .select("key, value_text")
    .in("key", [
      AGENT_CREATION_TOKEN_MINT_SETTING_KEY,
      AGENT_CREATION_TOKEN_MIN_AMOUNT_SETTING_KEY,
    ]);

  if (error) {
    console.warn("[agents] failed to read token gate settings", error);
    return {
      mint: null as string | null,
      requiredAmount: 0,
    };
  }

  const settings = new Map(
    (data ?? []).map((row) => [String(row.key), String(row.value_text ?? "")])
  );
  const mintRaw = settings.get(AGENT_CREATION_TOKEN_MINT_SETTING_KEY) ?? "";
  const mint = mintRaw.trim();
  const minAmountRaw =
    settings.get(AGENT_CREATION_TOKEN_MIN_AMOUNT_SETTING_KEY) ?? "0";
  const requiredAmount = parseNonNegativeNumber(minAmountRaw) ?? 0;

  return {
    mint: mint.length > 0 ? mint : null,
    requiredAmount,
  };
}

async function fetchSplTokenBalanceByMint({
  env,
  walletAddress,
  mint,
}: {
  env: Bindings;
  walletAddress: string;
  mint: string;
}) {
  const rpcUrl = (env.SOLANA_RPC_URL || "").trim() || DEFAULT_SOLANA_RPC_URL;
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "agent-creation-token-check",
      method: "getTokenAccountsByOwner",
      params: [
        walletAddress,
        { mint },
        {
          encoding: "jsonParsed",
        },
      ],
    }),
  });

  const payload = (await response.json().catch(() => null)) as
    | {
        error?: { message?: string };
        result?: {
          value?: Array<{
            account?: {
              data?: {
                parsed?: {
                  info?: {
                    tokenAmount?: {
                      uiAmountString?: string;
                      uiAmount?: number;
                    };
                  };
                };
              };
            };
          }>;
        };
      }
    | null;

  if (!response.ok) {
    throw new Error(`RPC request failed with status ${response.status}`);
  }
  if (payload?.error) {
    throw new Error(payload.error.message || "RPC returned an error");
  }

  let total = 0;
  for (const item of payload?.result?.value ?? []) {
    const tokenAmount = item?.account?.data?.parsed?.info?.tokenAmount;
    const asString = tokenAmount?.uiAmountString;
    const parsed = Number(
      typeof asString === "string" && asString.length > 0
        ? asString
        : tokenAmount?.uiAmount ?? 0
    );
    if (Number.isFinite(parsed) && parsed > 0) {
      total += parsed;
    }
  }

  return Number(total.toFixed(9));
}

async function evaluateAgentCreationEligibility({
  env,
  walletAddress,
}: {
  env: Bindings;
  walletAddress?: string | null;
}) {
  const settings = await getAgentCreationTokenGateSettings(env);
  if (!settings.mint) {
    return {
      enabled: true,
      eligible: false,
      mint: null,
      requiredAmount: settings.requiredAmount,
      currentAmount: null as number | null,
      reason:
        "Agent creation is paused and will be enabled right after the DSRV token is minted.",
      code: "TOKEN_GATE_MINT_NOT_CONFIGURED",
    };
  }

  if (settings.requiredAmount <= 0) {
    return {
      enabled: false,
      eligible: true,
      mint: settings.mint,
      requiredAmount: settings.requiredAmount,
      currentAmount: null as number | null,
      reason: null as string | null,
      code: null as string | null,
    };
  }

  const owner = String(walletAddress || "").trim();
  if (!owner) {
    return {
      enabled: true,
      eligible: false,
      mint: settings.mint,
      requiredAmount: settings.requiredAmount,
      currentAmount: null,
      reason: "Wallet address is missing for token-gated agent creation.",
      code: "TOKEN_GATE_WALLET_MISSING",
    };
  }

  try {
    const currentAmount = await fetchSplTokenBalanceByMint({
      env,
      walletAddress: owner,
      mint: settings.mint,
    });
    const eligible =
      currentAmount + ELIGIBILITY_EPSILON >= settings.requiredAmount;
    return {
      enabled: true,
      eligible,
      mint: settings.mint,
      requiredAmount: settings.requiredAmount,
      currentAmount,
      reason: eligible
        ? null
        : `Insufficient DSRV balance. Required ${settings.requiredAmount}, current ${currentAmount}.`,
      code: eligible ? null : "TOKEN_GATE_INSUFFICIENT_BALANCE",
    };
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown balance check error";
    console.warn("[agents] token gate balance check failed", { message });
    return {
      enabled: true,
      eligible: false,
      mint: settings.mint,
      requiredAmount: settings.requiredAmount,
      currentAmount: null,
      reason: "Unable to verify DSRV balance right now. Please try again.",
      code: "TOKEN_GATE_CHECK_FAILED",
    };
  }
}

async function getActiveAgentCountForLimit({
  env,
  userId,
}: {
  env: Bindings;
  userId: string;
}) {
  const supabase = getSupabaseClient(env);
  const { data, error } = await supabase
    .from("agents")
    .select("id, status, status_updated_at, updated_at, created_at, last_error")
    .eq("user_id", userId);
  if (error) {
    throw new Error("Failed to load user agents.");
  }

  let activeCount = 0;
  for (const row of data ?? []) {
    const normalized = normalizeAgentStatus(row.status);
    if (!ActiveAgentStatuses.includes(normalized)) continue;
    const timestamp = row.status_updated_at ?? row.updated_at ?? row.created_at ?? null;
    if (hasExpiredStatus(normalized, timestamp)) {
      await updateAgentStatus({
        env,
        id: row.id,
        userId,
        status: AgentStatus.Cancelled,
        lastError: row.last_error ?? "timeout",
      });
      continue;
    }
    activeCount += 1;
  }

  return activeCount;
}

async function upsertAgentRecord({
  env,
  id,
  userId,
  status,
  sessionId,
  network,
  lastError,
}: {
  env: Bindings;
  id: string;
  userId: string;
  status: AgentStatusValue;
  sessionId: string;
  network?: string | null;
  lastError?: string | null;
}) {
  const supabase = getSupabaseClient(env);
  const now = new Date().toISOString();
  const normalizedNetwork =
    String(network || "").toLowerCase() === "mainnet" ? "mainnet" : "testnet";
  const { error } = await supabase
    .from("agents")
    .upsert(
      {
        id,
        user_id: userId,
        status,
        session_id: sessionId,
        network: normalizedNetwork,
        status_updated_at: now,
        updated_at: now,
        last_error: lastError ?? null,
      },
      { onConflict: "id" }
    );
  if (error) {
    console.warn("[agents] upsert failed", error);
  }
}

async function updateAgentStatus({
  env,
  id,
  userId,
  status,
  sessionId,
  network,
  lastError,
}: {
  env: Bindings;
  id: string;
  userId?: string | null;
  status: AgentStatusValue;
  sessionId?: string | null;
  network?: string | null;
  lastError?: string | null;
}) {
  const supabase = getSupabaseClient(env);
  const now = new Date().toISOString();
  const update: Record<string, unknown> = {
    status,
    status_updated_at: now,
    updated_at: now,
  };
  if (typeof lastError !== "undefined") update.last_error = lastError;
  if (sessionId) update.session_id = sessionId;
  if (typeof network !== "undefined") {
    update.network = String(network || "").toLowerCase() === "mainnet" ? "mainnet" : "testnet";
  }
  let query = supabase.from("agents").update(update).eq("id", id);
  if (userId) query = query.eq("user_id", userId);
  const { data, error } = await query.select("id").maybeSingle();
  if (error) {
    console.warn("[agents] status update failed", error);
  }
  if (!data && userId && sessionId) {
    await upsertAgentRecord({
      env,
      id,
      userId,
      status,
      sessionId,
      network,
      lastError,
    });
  }
}

async function ensureAgentOwnership(env: Bindings, userId: string, agentId: string) {
  const supabase = getSupabaseClient(env);
  const { data, error } = await supabase
    .from("agents")
    .select("id")
    .eq("id", agentId)
    .eq("user_id", userId)
    .maybeSingle();
  if (error) {
    console.warn("[agents] ownership check failed", error);
    return false;
  }
  return Boolean(data);
}

async function ensureSystemPrompt({
  env,
  agentId,
  userId,
  systemPrompt,
}: {
  env: Bindings;
  agentId: string;
  userId: string;
  systemPrompt: string;
}) {
  if (!systemPrompt) return;
  const supabase = getSupabaseClient(env);
  const { count, error } = await supabase
    .from("agent_messages")
    .select("id", { count: "exact", head: true })
    .eq("agent_id", agentId)
    .eq("user_id", userId);
  if (error) {
    console.warn("[agents] system prompt check failed", error);
    return;
  }
  if ((count ?? 0) > 0) return;
  const { error: insertError } = await supabase.from("agent_messages").insert({
    agent_id: agentId,
    user_id: userId,
    role: "system",
    content: systemPrompt,
  });
  if (insertError) {
    console.warn("[agents] system prompt insert failed", insertError);
  }
}

async function insertAgentMessages({
  env,
  agentId,
  userId,
  messages,
}: {
  env: Bindings;
  agentId: string;
  userId: string;
  messages: Array<{ role: string; content: string }>;
}) {
  if (messages.length === 0) return;
  const supabase = getSupabaseClient(env);
  const { error } = await supabase.from("agent_messages").insert(
    messages.map((message) => ({
      agent_id: agentId,
      user_id: userId,
      role: message.role,
      content: message.content,
    }))
  );
  if (error) {
    console.warn("[agents] message insert failed", error);
  }
}

function extractAssistantReply(data: unknown) {
  const choices = (data as { choices?: Array<{ message?: { content?: string } }> })
    ?.choices;
  return choices?.[0]?.message?.content ?? "";
}

async function requireSession(c: Parameters<typeof agentRoutes.use>[0]) {
  const headerToken = c.req.header("authorization") ?? c.req.header("Authorization");
  const token = getCookie(c, "dt_session") ?? headerToken?.replace(/^Bearer\s+/i, "");
  if (!token) return { session: null, reason: "missing_token" };
  try {
    const secret = new TextEncoder().encode(c.env.AUTH_JWT_SECRET);
    const { payload } = await jwtVerify(token, secret);
    return { session: payload, reason: null };
  } catch (error) {
    const err = error as { code?: string; message?: string };
    console.warn("[auth] session verify failed", {
      code: err?.code,
      message: err?.message,
      hasSecret: Boolean(c.env.AUTH_JWT_SECRET),
    });
    return { session: null, reason: "invalid_token" };
  }
}

export const agentRoutes = new Hono<{ Bindings: Bindings }>()
  .get("/", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const supabase = getSupabaseClient(c.env);
    const { data, error } = await supabase
      .from("agents")
      .select(
        "id, name, status, session_id, network, created_at, updated_at, status_updated_at, live_started_at, initial_deposit_usd, current_balance_usd, current_balance_updated_at, last_error"
      )
      .eq("user_id", String(session.sub))
      .order("created_at", { ascending: false });

    if (error) {
      return c.json({ error: "Failed to load agents." }, 500);
    }

    const nowIso = new Date().toISOString();
    const agents = await Promise.all(
      (data ?? []).map(async (row) => {
        const normalized = normalizeAgentStatus(row.status);
        const timestamp =
          row.status_updated_at ?? row.updated_at ?? row.created_at ?? null;
        const initialDepositUsd =
          row.initial_deposit_usd === null ||
          typeof row.initial_deposit_usd === "undefined"
            ? null
            : Number(row.initial_deposit_usd);
        const currentBalanceUsd =
          row.current_balance_usd === null ||
          typeof row.current_balance_usd === "undefined"
            ? null
            : Number(row.current_balance_usd);
        const hasPnlInputs =
          typeof initialDepositUsd === "number" &&
          Number.isFinite(initialDepositUsd) &&
          typeof currentBalanceUsd === "number" &&
          Number.isFinite(currentBalanceUsd);
        const pnlUsd =
          hasPnlInputs
            ? Number((currentBalanceUsd - initialDepositUsd).toFixed(6))
            : null;
        const pnlPercent =
          hasPnlInputs && initialDepositUsd > 0
            ? Number(
                (
                  ((currentBalanceUsd - initialDepositUsd) / initialDepositUsd) *
                  100
                ).toFixed(6)
              )
            : null;

        const baseRow = {
          ...row,
          status: normalized,
          network: row.network || "testnet",
          initial_deposit_usd: initialDepositUsd,
          current_balance_usd: currentBalanceUsd,
          pnl_usd: pnlUsd,
          pnl_percent: pnlPercent,
        };

        if (hasExpiredStatus(normalized, timestamp)) {
          await updateAgentStatus({
            env: c.env,
            id: row.id,
            userId: String(session.sub),
            status: AgentStatus.Cancelled,
            lastError: row.last_error ?? "timeout",
          });
          return {
            ...baseRow,
            status: AgentStatus.Cancelled,
            status_updated_at: nowIso,
            last_error: row.last_error ?? "timeout",
          };
        }

        return baseRow;
      })
    );

    return c.json({ agents });
  })
  .get("/creation-eligibility", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const eligibility = await evaluateAgentCreationEligibility({
      env: c.env,
      walletAddress:
        typeof session.walletAddress === "string" ? session.walletAddress : null,
    });

    return c.json({
      eligibility: {
        enabled: eligibility.enabled,
        eligible: eligibility.eligible,
        mint: eligibility.mint,
        requiredAmount: eligibility.requiredAmount,
        currentAmount: eligibility.currentAmount,
        reason: eligibility.reason,
        code: eligibility.code,
      },
    });
  })
  .get("/active", async (c) => {
    if (!coreTokenAllowed(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const supabase = getSupabaseClient(c.env);
    const { data, error } = await supabase
      .from("agents")
      .select(
        "id, name, user_id, status, session_id, network, created_at, updated_at, status_updated_at"
      );

    if (error) {
      return c.json({ error: "Failed to load agents." }, 500);
    }

    const now = new Date().toISOString();
    const agents = await Promise.all(
      (data ?? []).map(async (row) => {
        const normalized = normalizeAgentStatus(row.status);
        const timestamp =
          row.status_updated_at ?? row.updated_at ?? row.created_at ?? null;
        if (!ActiveAgentStatuses.includes(normalized)) {
          return null;
        }
        if (hasExpiredStatus(normalized, timestamp)) {
          await updateAgentStatus({
            env: c.env,
            id: row.id,
            userId: row.user_id,
            status: AgentStatus.Cancelled,
            lastError: "timeout",
          });
          return null;
        }
        return {
          ...row,
          status: normalized,
          network: row.network || "testnet",
          status_updated_at: row.status_updated_at ?? now,
        };
      })
    );

    const filtered = agents.filter(
      (agent): agent is NonNullable<typeof agent> => Boolean(agent)
    );
    return c.json({ agents: filtered });
  })
  .get("/public/market", async (c) => {
    const requestedLimit = Number.parseInt(c.req.query("limit") || "20", 10);
    const limit = Number.isFinite(requestedLimit)
      ? Math.max(1, Math.min(100, requestedLimit))
      : 20;

    const supabase = getSupabaseClient(c.env);
    const { data, error } = await supabase
      .from("agents")
      .select(
        "id, name, user_id, status, network, created_at, status_updated_at, live_started_at, initial_deposit_usd, current_balance_usd, current_balance_updated_at"
      )
      .in("status", [AgentStatus.LiveTrading, AgentStatus.Stopped])
      .order("created_at", { ascending: false })
      .limit(500);

    if (error) {
      return c.json({ error: "Failed to load market agents." }, 500);
    }

    const normalizedRows = (data ?? [])
      .map((row) => ({ ...row, status: normalizeAgentStatus(row.status) }))
      .filter(
        (row) =>
          row.status === AgentStatus.LiveTrading || row.status === AgentStatus.Stopped
      );

    const userIds = Array.from(
      new Set(
        normalizedRows
          .map((row) => String(row.user_id || "").trim())
          .filter(Boolean)
      )
    );

    let walletByUserId = new Map<string, string>();
    if (userIds.length > 0) {
      const { data: usersData } = await supabase
        .from("users")
        .select("id, wallet_address")
        .in("id", userIds);
      walletByUserId = new Map(
        (usersData ?? [])
          .map((row) => [String(row.id), String(row.wallet_address || "")])
          .filter(([, wallet]) => Boolean(wallet))
      );
    }

    const marketAgents = normalizedRows
      .map((row) => {
        const initialDepositUsd =
          row.initial_deposit_usd === null ||
          typeof row.initial_deposit_usd === "undefined"
            ? null
            : Number(row.initial_deposit_usd);
        const currentBalanceUsd =
          row.current_balance_usd === null ||
          typeof row.current_balance_usd === "undefined"
            ? null
            : Number(row.current_balance_usd);
        const hasPnlInputs =
          typeof initialDepositUsd === "number" &&
          Number.isFinite(initialDepositUsd) &&
          typeof currentBalanceUsd === "number" &&
          Number.isFinite(currentBalanceUsd);
        const pnlUsd =
          hasPnlInputs
            ? Number((currentBalanceUsd - initialDepositUsd).toFixed(6))
            : null;
        const pnlPercent =
          hasPnlInputs && initialDepositUsd > 0
            ? Number(
                (
                  ((currentBalanceUsd - initialDepositUsd) / initialDepositUsd) *
                  100
                ).toFixed(6)
              )
            : null;
        return {
          id: row.id,
          name: normalizeProposedAgentName(row.name) ?? null,
          status: row.status,
          network:
            String(row.network || "testnet").toLowerCase() === "mainnet"
              ? "mainnet"
              : "testnet",
          authorWalletAddress: walletByUserId.get(String(row.user_id)) || null,
          initialDepositUsd,
          currentBalanceUsd,
          pnlUsd,
          pnlPercent,
          liveStartedAt: row.live_started_at ?? null,
          createdAt: row.created_at ?? null,
          statusUpdatedAt: row.status_updated_at ?? null,
          currentBalanceUpdatedAt: row.current_balance_updated_at ?? null,
        };
      })
      .sort((a, b) => {
        const left = typeof a.pnlUsd === "number" ? a.pnlUsd : Number.NEGATIVE_INFINITY;
        const right = typeof b.pnlUsd === "number" ? b.pnlUsd : Number.NEGATIVE_INFINITY;
        if (right !== left) return right - left;
        return (b.liveStartedAt || b.createdAt || "").localeCompare(
          a.liveStartedAt || a.createdAt || ""
        );
      })
      .slice(0, limit);

    return c.json({ agents: marketAgents });
  })
  .post("/start", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);
    const coreHeaders = buildCoreHeaders(c.env);
    if (!coreHeaders) {
      return c.json({ error: "CORE_SERVICE_TOKEN not configured" }, 500);
    }

    const userId = String(session.sub);
    try {
      const [maxAgentsPerUser, activeAgentCount] = await Promise.all([
        getMaxAgentsPerUserSetting(c.env),
        getActiveAgentCountForLimit({
          env: c.env,
          userId,
        }),
      ]);
      if (activeAgentCount >= maxAgentsPerUser) {
        return c.json(
          {
            error: `Agent limit reached: maximum ${maxAgentsPerUser} active agent(s) per user.`,
            code: "AGENT_LIMIT_REACHED",
            limit: maxAgentsPerUser,
            activeAgents: activeAgentCount,
          },
          409
        );
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to enforce agent limit.";
      return c.json({ error: message }, 500);
    }

    const creationEligibility = await evaluateAgentCreationEligibility({
      env: c.env,
      walletAddress:
        typeof session.walletAddress === "string" ? session.walletAddress : null,
    });
    if (creationEligibility.enabled && !creationEligibility.eligible) {
      const statusCode =
        creationEligibility.code === "TOKEN_GATE_CHECK_FAILED" ||
        creationEligibility.code === "TOKEN_GATE_MINT_NOT_CONFIGURED"
          ? 503
          : 409;
      return c.json(
        {
          error:
            creationEligibility.reason ||
            "Insufficient DSRV balance for agent creation.",
          code: creationEligibility.code || "TOKEN_GATE_INSUFFICIENT_BALANCE",
          mint: creationEligibility.mint,
          requiredAmount: creationEligibility.requiredAmount,
          currentAmount: creationEligibility.currentAmount,
          eligible: false,
        },
        statusCode
      );
    }

    const payload = await c.req.json().catch(() => ({}));
    const response = await fetch(`${coreUrl}/agents/start`, {
      method: "POST",
      headers: coreHeaders,
      body: JSON.stringify({
        userId,
        walletAddress: session.walletAddress,
        ...payload,
      }),
    });

    const data = await response.json();
    if (response.ok) {
      const normalized = normalizeAgentStatus(data.status);
      if (data.agentId && data.sessionId) {
        await upsertAgentRecord({
          env: c.env,
          id: data.agentId,
          userId,
          status: normalized,
          sessionId: data.sessionId,
          network: data.network,
        });
      }
      data.status = normalized;
      data.network = String(data.network || "testnet").toLowerCase() === "mainnet"
        ? "mainnet"
        : "testnet";
    }
    return c.json(data, response.status);
  })
  .post("/:id/status", async (c) => {
    if (!coreTokenAllowed(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const payload = await c.req.json().catch(() => ({}));
    if (!payload?.status) {
      return c.json({ error: "status is required" }, 400);
    }
    const normalized = normalizeAgentStatus(payload.status);
    await updateAgentStatus({
      env: c.env,
      id: c.req.param("id"),
      userId: payload.userId ?? null,
      status: normalized,
      sessionId: payload.sessionId ?? null,
      network: payload.network ?? null,
      lastError: payload.lastError ?? null,
    });
    return c.json({ ok: true, status: normalized });
  })
  .get("/:id/status", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const lookupId = c.req.param("id");
    const supabase = getSupabaseClient(c.env);
    const { data: bySession, error: sessionError } = await supabase
      .from("agents")
      .select(
        "id, session_id, status, network, status_updated_at, updated_at, created_at, last_error"
      )
      .eq("session_id", lookupId)
      .eq("user_id", String(session.sub))
      .maybeSingle();
    if (sessionError) {
      return c.json({ error: "Failed to load agent." }, 500);
    }

    let agentRow = bySession ?? null;
    if (!agentRow) {
      const { data: byAgent, error: agentError } = await supabase
        .from("agents")
        .select(
          "id, session_id, status, network, status_updated_at, updated_at, created_at, last_error"
        )
        .eq("id", lookupId)
        .eq("user_id", String(session.sub))
        .maybeSingle();
      if (agentError) {
        return c.json({ error: "Failed to load agent." }, 500);
      }
      agentRow = byAgent ?? null;
    }

    if (!agentRow) return c.json({ error: "Agent not found" }, 404);
    const sessionId = String(agentRow.session_id || "");
    if (!sessionId) return c.json({ error: "Agent session missing" }, 409);

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);
    const coreHeaders = buildCoreHeaders(c.env, { json: false });
    if (!coreHeaders) {
      return c.json({ error: "CORE_SERVICE_TOKEN not configured" }, 500);
    }

    const response = await fetch(`${coreUrl}/agents/${sessionId}`, {
      method: "GET",
      headers: coreHeaders,
    });
    const data = await response.json();
    if (response.ok) {
      const normalized = normalizeAgentStatus(data.status);
      data.status = normalized;
      const agentId = data.agentId ?? agentRow.id;
      data.agentId = agentId;
      data.sessionId = sessionId;
      data.network =
        String(data.network || agentRow.network || "testnet").toLowerCase() === "mainnet"
          ? "mainnet"
          : "testnet";
      data.statusUpdatedAt =
        agentRow.status_updated_at ?? agentRow.updated_at ?? agentRow.created_at ?? null;
      const previousStatus = normalizeAgentStatus(agentRow.status);
      if (agentId) {
        if (normalized !== previousStatus || data.error) {
          await updateAgentStatus({
            env: c.env,
            id: agentId,
            userId: String(session.sub),
            status: normalized,
            sessionId,
            network: data.network,
            lastError: data.error ?? null,
          });
        }
      }
    }
    return c.json(data, response.status);
  })
  .get("/:id/messages", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const agentId = c.req.param("id");
    const userId = String(session.sub);
    const ownsAgent = await ensureAgentOwnership(c.env, userId, agentId);
    if (!ownsAgent) return c.json({ error: "Agent not found" }, 404);

    const supabase = getSupabaseClient(c.env);
    const { data, error } = await supabase
      .from("agent_messages")
      .select("role, content, created_at")
      .eq("agent_id", agentId)
      .eq("user_id", userId)
      .order("created_at", { ascending: true });

    if (error) {
      return c.json({ error: "Failed to load messages." }, 500);
    }

    return c.json({ messages: data ?? [] });
  })
  .get("/:id/public", async (c) => {
    const agentId = c.req.param("id");
    const supabase = getSupabaseClient(c.env);
    const { data: agentRow, error: agentError } = await supabase
      .from("agents")
      .select(
        "id, name, user_id, status, network, initial_deposit_usd, current_balance_usd, current_balance_updated_at, ai_credits_remaining_percent, ai_credits_resets_in, ai_credits_updated_at, live_started_at, created_at, updated_at, status_updated_at"
      )
      .eq("id", agentId)
      .maybeSingle();
    if (agentError) {
      return c.json({ error: "Failed to load agent." }, 500);
    }
    if (!agentRow) return c.json({ error: "Agent not found" }, 404);
    const status = normalizeAgentStatus(agentRow.status);

    const { data: userRow } = await supabase
      .from("users")
      .select("wallet_address")
      .eq("id", agentRow.user_id)
      .maybeSingle();

    const { data: walletRow } = await supabase
      .from("agent_wallets")
      .select("public_address, exchange")
      .eq("agent_id", agentId)
      .eq("exchange", "hyperliquid")
      .eq("role", "master")
      .maybeSingle();

    const initialDepositUsd =
      agentRow.initial_deposit_usd === null ||
      typeof agentRow.initial_deposit_usd === "undefined"
        ? null
        : Number(agentRow.initial_deposit_usd);
    const currentBalanceUsd =
      agentRow.current_balance_usd === null ||
      typeof agentRow.current_balance_usd === "undefined"
        ? null
        : Number(agentRow.current_balance_usd);
    const hasPnlInputs =
      typeof initialDepositUsd === "number" &&
      Number.isFinite(initialDepositUsd) &&
      typeof currentBalanceUsd === "number" &&
      Number.isFinite(currentBalanceUsd);
    const pnlUsd =
      hasPnlInputs
        ? Number((currentBalanceUsd - initialDepositUsd).toFixed(6))
        : null;
    const pnlPercent =
      hasPnlInputs && initialDepositUsd > 0
        ? Number((((currentBalanceUsd - initialDepositUsd) / initialDepositUsd) * 100).toFixed(6))
        : null;
    const hasLiveStarted = Boolean(agentRow.live_started_at);
    const canExposeDepositAddress =
      !hasLiveStarted && status === AgentStatus.AwaitingDeposit;

    return c.json({
      agent: {
        id: agentRow.id,
        name: normalizeProposedAgentName(agentRow.name) ?? null,
        status,
        network: String(agentRow.network || "testnet").toLowerCase() === "mainnet"
          ? "mainnet"
          : "testnet",
        authorWalletAddress: userRow?.wallet_address ?? null,
        initialDepositUsd,
        currentBalanceUsd,
        pnlUsd,
        pnlPercent,
        currentBalanceUpdatedAt: agentRow.current_balance_updated_at ?? null,
        aiCreditsRemainingPercent:
          agentRow.ai_credits_remaining_percent === null ||
          typeof agentRow.ai_credits_remaining_percent === "undefined"
            ? null
            : Number(agentRow.ai_credits_remaining_percent),
        aiCreditsResetsIn:
          typeof agentRow.ai_credits_resets_in === "string" &&
          agentRow.ai_credits_resets_in.trim()
            ? agentRow.ai_credits_resets_in.trim()
            : null,
        aiCreditsUpdatedAt: agentRow.ai_credits_updated_at ?? null,
        liveStartedAt: agentRow.live_started_at ?? null,
        createdAt: agentRow.created_at ?? null,
        statusUpdatedAt:
          agentRow.status_updated_at ?? agentRow.updated_at ?? agentRow.created_at ?? null,
        depositAddress: canExposeDepositAddress ? walletRow?.public_address ?? null : null,
      },
    });
  })
  .get("/:id/public-logs", async (c) => {
    const agentId = c.req.param("id");
    const requestedLimit = Number.parseInt(c.req.query("limit") || "20", 10);
    const limit = Number.isFinite(requestedLimit)
      ? Math.max(1, Math.min(100, requestedLimit))
      : 20;
    const before = String(c.req.query("before") || "").trim();
    const hasValidBefore = Boolean(before) && Number.isFinite(Date.parse(before));
    const supabase = getSupabaseClient(c.env);
    let query = supabase
      .from("agent_public_logs")
      .select("id, message, kind, created_at")
      .eq("agent_id", agentId)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false });
    if (hasValidBefore) {
      query = query.lt("created_at", before);
    }
    const { data, error } = await query.limit(limit + 1);
    if (error) {
      return c.json({ error: "Failed to load logs." }, 500);
    }
    const rows = data ?? [];
    const hasMore = rows.length > limit;
    const pageRows = hasMore ? rows.slice(0, limit) : rows;
    const nextBefore = hasMore
      ? pageRows[pageRows.length - 1]?.created_at ?? null
      : null;
    return c.json({
      logs: pageRows.reverse(),
      page: {
        limit,
        hasMore,
        nextBefore,
      },
    });
  })
  .post("/:id/confirm", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const agentId = c.req.param("id");
    const userId = String(session.sub);
    const ownsAgent = await ensureAgentOwnership(c.env, userId, agentId);
    if (!ownsAgent) return c.json({ error: "Agent not found" }, 404);

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);
    const coreHeaders = buildCoreHeaders(c.env);
    if (!coreHeaders) {
      return c.json({ error: "CORE_SERVICE_TOKEN not configured" }, 500);
    }
    const proposedName = await resolveProposedAgentName({
      env: c.env,
      agentId,
      userId,
    });

    const response = await fetch(`${coreUrl}/agents/${agentId}/confirm`, {
      method: "POST",
      headers: coreHeaders,
      body: JSON.stringify({ userId, strategyName: proposedName }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return c.json(
        { error: data?.error || "Failed to confirm strategy." },
        response.status
      );
    }

    if (data?.status) {
      const normalized = normalizeAgentStatus(data.status);
      await updateAgentStatus({
        env: c.env,
        id: agentId,
        userId,
        status: normalized,
        sessionId: data.sessionId ?? null,
        network: data.network ?? null,
        lastError: data.error ?? null,
      });
      data.status = normalized;
    }
    const normalizedName =
      normalizeProposedAgentName(data?.name) ?? normalizeProposedAgentName(proposedName);
    if (normalizedName) {
      await updateAgentName({
        env: c.env,
        id: agentId,
        userId,
        name: normalizedName,
      });
      data.name = normalizedName;
    }

    return c.json(data);
  })
  .delete("/:id", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const agentId = c.req.param("id");
    const userId = String(session.sub);
    const supabase = getSupabaseClient(c.env);
    const { data: agentRow, error: agentError } = await supabase
      .from("agents")
      .select("id, status")
      .eq("id", agentId)
      .eq("user_id", userId)
      .maybeSingle();

    if (agentError) {
      return c.json({ error: "Failed to load agent." }, 500);
    }
    if (!agentRow) {
      return c.json({ error: "Agent not found" }, 404);
    }
    const status = normalizeAgentStatus(agentRow.status);
    if (status === AgentStatus.LiveTrading) {
      return c.json({ error: "Cannot delete a live trading agent." }, 409);
    }

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);
    const coreHeaders = buildCoreHeaders(c.env);
    if (!coreHeaders) {
      return c.json({ error: "CORE_SERVICE_TOKEN not configured" }, 500);
    }

    const coreResponse = await fetch(`${coreUrl}/agents/${agentId}`, {
      method: "DELETE",
      headers: coreHeaders,
      body: JSON.stringify({ userId }),
    });
    if (!coreResponse.ok) {
      const payload = await coreResponse.json().catch(() => ({}));
      return c.json(
        { error: payload?.error || "Failed to stop agent." },
        coreResponse.status
      );
    }

    const { error: deleteError } = await supabase
      .from("agents")
      .delete()
      .eq("id", agentId)
      .eq("user_id", userId);
    if (deleteError) {
      return c.json({ error: "Failed to delete agent." }, 500);
    }

    return c.json({ ok: true });
  })
  .post("/:id/withdraw", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const agentId = c.req.param("id");
    const userId = String(session.sub);
    const payload = await c.req.json().catch(() => ({}));
    const destination = String(payload?.destination || "").trim();
    if (!destination) {
      return c.json({ error: "destination is required" }, 400);
    }

    const supabase = getSupabaseClient(c.env);
    const { data: agentRow, error: agentError } = await supabase
      .from("agents")
      .select("id, status")
      .eq("id", agentId)
      .eq("user_id", userId)
      .maybeSingle();

    if (agentError) {
      return c.json({ error: "Failed to load agent." }, 500);
    }
    if (!agentRow) return c.json({ error: "Agent not found" }, 404);

    const status = normalizeAgentStatus(agentRow.status);
    if (status !== AgentStatus.Stopped) {
      return c.json({ error: "Withdrawals are only available when stopped." }, 409);
    }

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);
    const coreHeaders = buildCoreHeaders(c.env);
    if (!coreHeaders) {
      return c.json({ error: "CORE_SERVICE_TOKEN not configured" }, 500);
    }

    const response = await fetch(`${coreUrl}/agents/${agentId}/withdraw`, {
      method: "POST",
      headers: coreHeaders,
      body: JSON.stringify({ userId, destination }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      return c.json({ error: data?.error || "Failed to withdraw." }, response.status);
    }

    return c.json(data);
  })
  .post("/:id/submit", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);
    const coreHeaders = buildCoreHeaders(c.env);
    if (!coreHeaders) {
      return c.json({ error: "CORE_SERVICE_TOKEN not configured" }, 500);
    }

    const payload = await c.req.json().catch(() => ({}));
    const response = await fetch(`${coreUrl}/agents/${c.req.param("id")}/submit`, {
      method: "POST",
      headers: coreHeaders,
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    return c.json(data, response.status);
  })
  .post("/:id/chat", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const agentId = c.req.param("id");
    const userId = String(session.sub);
    const ownsAgent = await ensureAgentOwnership(c.env, userId, agentId);
    if (!ownsAgent) return c.json({ error: "Agent not found" }, 404);
    const supabase = getSupabaseClient(c.env);
    const { data: agentRow, error: agentError } = await supabase
      .from("agents")
      .select("status")
      .eq("id", agentId)
      .eq("user_id", userId)
      .maybeSingle();
    if (agentError) {
      return c.json({ error: "Failed to load agent." }, 500);
    }
    if (!agentRow) return c.json({ error: "Agent not found" }, 404);
    if (normalizeAgentStatus(agentRow.status) !== AgentStatus.StrategyBuilding) {
      return c.json(
        { error: "Chat is read-only after strategy confirmation." },
        409
      );
    }

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);
    const coreHeaders = buildCoreHeaders(c.env);
    if (!coreHeaders) {
      return c.json({ error: "CORE_SERVICE_TOKEN not configured" }, 500);
    }

    const payload = await c.req.json().catch(() => ({}));
    const payloadMessages = Array.isArray(payload.messages) ? payload.messages : [];
    const response = await fetch(`${coreUrl}/agents/${c.req.param("id")}/chat`, {
      method: "POST",
      headers: coreHeaders,
      body: JSON.stringify({
        userId,
        walletAddress: session.walletAddress,
        ...payload,
      }),
    });
    const data = await response.json();
    if (response.ok) {
      const systemMessage = payloadMessages.find(
        (message) => message?.role === "system" && message?.content
      );
      if (systemMessage?.content) {
        await ensureSystemPrompt({
          env: c.env,
          agentId,
          userId,
          systemPrompt: String(systemMessage.content),
        });
      }
      const lastUserMessage = [...payloadMessages]
        .reverse()
        .find((message) => message?.role === "user" && message?.content);
      const assistantReply = extractAssistantReply(data);
      const messagesToStore: Array<{ role: string; content: string }> = [];
      if (lastUserMessage?.content) {
        messagesToStore.push({
          role: "user",
          content: String(lastUserMessage.content),
        });
      }
      if (assistantReply) {
        messagesToStore.push({ role: "assistant", content: String(assistantReply) });
      }
      await insertAgentMessages({
        env: c.env,
        agentId,
        userId,
        messages: messagesToStore,
      });
    }
    return c.json(data, response.status);
  });
