import { Hono } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { SignJWT, jwtVerify } from "jose";
import { getSupabaseClient } from "../lib/supabase";
import { buildAuthMessage, isTimestampFresh, verifySignature } from "../lib/wallet-auth";
import type { Bindings } from "../types/env";

type AuthUser = {
  id: string;
  wallet_address: string;
};

const SESSION_COOKIE = "dt_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;

function applyCorsHeaders(c: {
  req: { header: (name: string) => string | undefined };
  env: Bindings;
  header: (name: string, value: string) => void;
}) {
  const origin = c.req.header("origin");
  const allowlist = (c.env.APP_ORIGIN ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  const allowOrigin =
    allowlist.length === 0
      ? origin ?? "*"
      : origin && allowlist.includes(origin)
        ? origin
        : "";

  if (allowOrigin) {
    c.header("Access-Control-Allow-Origin", allowOrigin);
    c.header("Access-Control-Allow-Credentials", "true");
    c.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    c.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  }
}

async function getOrCreateUser(walletAddress: string, env: Bindings): Promise<AuthUser> {
  const supabase = getSupabaseClient(env);

  const { data: existing, error: fetchError } = await supabase
    .from("users")
    .select("id, wallet_address")
    .eq("wallet_address", walletAddress)
    .maybeSingle<AuthUser>();

  if (fetchError) {
    throw fetchError;
  }

  if (existing) {
    await supabase
      .from("users")
      .update({ last_login_at: new Date().toISOString() })
      .eq("id", existing.id);
    return existing;
  }

  const { data: created, error: createError } = await supabase
    .from("users")
    .insert({
      wallet_address: walletAddress,
      auth_provider: "phantom",
      last_login_at: new Date().toISOString(),
    })
    .select("id, wallet_address")
    .single<AuthUser>();

  if (createError || !created) {
    throw createError ?? new Error("Failed to create user.");
  }

  return created;
}

async function createSessionToken(user: AuthUser, env: Bindings) {
  const secret = new TextEncoder().encode(env.AUTH_JWT_SECRET);
  return new SignJWT({
    walletAddress: user.wallet_address,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(user.id)
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(secret);
}

async function verifySessionToken(token: string, env: Bindings) {
  const secret = new TextEncoder().encode(env.AUTH_JWT_SECRET);
  const { payload } = await jwtVerify(token, secret);
  return payload;
}

function buildCookieOptions(c: Parameters<typeof setCookie>[0], env: Bindings) {
  const isSecure = new URL(c.req.url).protocol === "https:";
  return {
    httpOnly: true,
    sameSite: "Lax" as const,
    secure: isSecure,
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS,
    domain: env.COOKIE_DOMAIN || undefined,
  };
}

export const authRoutes = new Hono<{ Bindings: Bindings }>()
  .use("*", async (c, next) => {
    applyCorsHeaders(c);
    if (c.req.method === "OPTIONS") {
      return c.body(null, 204);
    }
    await next();
  })
  .post("/phantom/message", async (c) => {
    const body = await c.req.json<{ walletAddress?: string }>();
    const walletAddress = body.walletAddress?.trim();
    if (!walletAddress) {
      return c.json({ error: "walletAddress is required." }, 400);
    }

    const domain =
      c.env.APP_DOMAIN?.trim() || new URL(c.req.url).origin;
    const timestamp = new Date().toISOString();
    const message = buildAuthMessage({ domain, walletAddress, timestamp });

    return c.json({ message, timestamp });
  })
  .post("/phantom/verify", async (c) => {
    const body = await c.req.json<{
      walletAddress?: string;
      signature?: string;
      message?: string;
      timestamp?: string;
    }>();

    const walletAddress = body.walletAddress?.trim();
    const signature = body.signature?.trim();
    const message = body.message?.trim();
    const timestamp = body.timestamp?.trim();

    if (!walletAddress || !signature || !message || !timestamp) {
      return c.json({ error: "Missing required fields." }, 400);
    }

    if (!isTimestampFresh(timestamp)) {
      return c.json({ error: "Signature expired. Please try again." }, 401);
    }

    const domain =
      c.env.APP_DOMAIN?.trim() || new URL(c.req.url).origin;
    const expectedMessage = buildAuthMessage({
      domain,
      walletAddress,
      timestamp,
    });

    if (expectedMessage !== message) {
      return c.json({ error: "Invalid authentication message." }, 401);
    }

    const isValid = await verifySignature({
      message,
      signature,
      walletAddress,
    });

    if (!isValid) {
      return c.json({ error: "Signature verification failed." }, 401);
    }

    const user = await getOrCreateUser(walletAddress, c.env);
    const token = await createSessionToken(user, c.env);
    setCookie(c, SESSION_COOKIE, token, buildCookieOptions(c, c.env));

    return c.json({ ok: true, user, token });
  })
  .get("/session", async (c) => {
    const headerToken = c.req.header("authorization")?.replace(/^Bearer\s+/i, "");
    const cookieToken = getCookie(c, SESSION_COOKIE);
    const token = cookieToken || headerToken;

    if (!token) {
      return c.json({ authenticated: false }, 401);
    }

    try {
      const payload = await verifySessionToken(token, c.env);
      return c.json({
        authenticated: true,
        user: {
          id: payload.sub,
          walletAddress: payload.walletAddress,
        },
      });
    } catch (error) {
      return c.json({ authenticated: false }, 401);
    }
  })
  .post("/logout", async (c) => {
    deleteCookie(c, SESSION_COOKIE, {
      path: "/",
      domain: c.env.COOKIE_DOMAIN || undefined,
    });
    return c.json({ ok: true });
  });
