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
  return null;
}

function hasExpiredStatus(status: AgentStatusValue, timestamp?: string | null) {
  if (!timestamp) return false;
  const ttl = statusTimeoutMs(status);
  if (!ttl) return false;
  const elapsed = Date.now() - new Date(timestamp).getTime();
  return elapsed > ttl;
}

function coreTokenAllowed(c: Parameters<typeof agentRoutes.use>[0]) {
  if (!c.env.CORE_API_TOKEN) return true;
  const headerToken =
    c.req.header("x-core-token") ??
    c.req.header("authorization")?.replace(/^Bearer\s+/i, "");
  return Boolean(headerToken && headerToken === c.env.CORE_API_TOKEN);
}

async function upsertAgentRecord({
  env,
  id,
  userId,
  status,
  sessionId,
  lastError,
}: {
  env: Bindings;
  id: string;
  userId: string;
  status: AgentStatusValue;
  sessionId: string;
  lastError?: string | null;
}) {
  const supabase = getSupabaseClient(env);
  const now = new Date().toISOString();
  const { error } = await supabase
    .from("agents")
    .upsert(
      {
        id,
        user_id: userId,
        status,
        session_id: sessionId,
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
  lastError,
}: {
  env: Bindings;
  id: string;
  userId?: string | null;
  status: AgentStatusValue;
  sessionId?: string | null;
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
        "id, status, session_id, created_at, updated_at, status_updated_at, last_error"
      )
      .eq("user_id", String(session.sub))
      .order("created_at", { ascending: false });

    if (error) {
      return c.json({ error: "Failed to load agents." }, 500);
    }

    const now = new Date().toISOString();
    const agents = await Promise.all(
      (data ?? []).map(async (row) => {
        const normalized = normalizeAgentStatus(row.status);
        const timestamp =
          row.status_updated_at ?? row.updated_at ?? row.created_at ?? null;
        if (hasExpiredStatus(normalized, timestamp)) {
          await updateAgentStatus({
            env: c.env,
            id: row.id,
            userId: String(session.sub),
            status: AgentStatus.Cancelled,
            lastError: row.last_error ?? "timeout",
          });
          return {
            ...row,
            status: AgentStatus.Cancelled,
            status_updated_at: now,
            last_error: row.last_error ?? "timeout",
          };
        }
        return { ...row, status: normalized };
      })
    );

    return c.json({ agents });
  })
  .get("/active", async (c) => {
    if (!coreTokenAllowed(c)) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const supabase = getSupabaseClient(c.env);
    const { data, error } = await supabase
      .from("agents")
      .select(
        "id, user_id, status, session_id, created_at, updated_at, status_updated_at"
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
        return { ...row, status: normalized, status_updated_at: row.status_updated_at ?? now };
      })
    );

    const filtered = agents.filter(
      (agent): agent is NonNullable<typeof agent> => Boolean(agent)
    );
    return c.json({ agents: filtered });
  })
  .post("/start", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);

    const payload = await c.req.json().catch(() => ({}));
    const response = await fetch(`${coreUrl}/agents/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: session.sub,
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
          userId: String(session.sub),
          status: normalized,
          sessionId: data.sessionId,
        });
      }
      data.status = normalized;
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
      .select("id, session_id, status, status_updated_at, updated_at, created_at, last_error")
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
        .select("id, session_id, status, status_updated_at, updated_at, created_at, last_error")
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

    const response = await fetch(`${coreUrl}/agents/${sessionId}`, {
      method: "GET",
    });
    const data = await response.json();
    if (response.ok) {
      const normalized = normalizeAgentStatus(data.status);
      data.status = normalized;
      const agentId = data.agentId ?? agentRow.id;
      data.agentId = agentId;
      data.sessionId = sessionId;
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

    const coreResponse = await fetch(`${coreUrl}/agents/${agentId}`, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
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
  .post("/:id/submit", async (c) => {
    const { session, reason } = await requireSession(c);
    if (!session) return c.json({ error: "Unauthorized", reason }, 401);

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);

    const payload = await c.req.json().catch(() => ({}));
    const response = await fetch(`${coreUrl}/agents/${c.req.param("id")}/submit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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

    const coreUrl = c.env.CORE_URL?.replace(/\/$/, "");
    if (!coreUrl) return c.json({ error: "CORE_URL not configured" }, 500);

    const payload = await c.req.json().catch(() => ({}));
    const payloadMessages = Array.isArray(payload.messages) ? payload.messages : [];
    const response = await fetch(`${coreUrl}/agents/${c.req.param("id")}/chat`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
