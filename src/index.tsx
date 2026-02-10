import { Hono } from "hono";
import { renderer } from "./renderer";
import { authRoutes } from "./routes/auth";
import type { Bindings } from "./types/env";

const app = new Hono<{ Bindings: Bindings }>();

app.use("*", async (c, next) => {
  const origin = c.req.header("origin");
  const allowlist = (c.env.APP_ORIGIN ?? "")
    .split(",")
    .map((item: string) => item.trim())
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

  if (c.req.method === "OPTIONS") {
    return c.body(null, 204);
  }

  await next();
});

app.use(renderer);
app.route("/auth", authRoutes);

app.get("/", (c) => {
  return c.render(<h1>Hello!</h1>);
});

export default app;
