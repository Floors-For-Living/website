import { createClient } from "npm:@supabase/supabase-js@2";

const ALLOWED_ORIGINS = [
  "https://floorsforliving.co.uk",
  "https://www.floorsforliving.co.uk",
];
const INTERESTS = ["Carpet", "LVT", "Vinyl", "Real wood", "Bespoke", "Accessories", "Not sure yet"];
const RATE_LIMIT = 5; // submissions per IP per window
const RATE_WINDOW_MS = 60 * 60 * 1000;

const db = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false } },
);

function cors(req: Request) {
  const origin = req.headers.get("origin") ?? "";
  const allowed = ALLOWED_ORIGINS.includes(origin) || /^http:\/\/localhost(:\d+)?$/.test(origin);
  return {
    "Access-Control-Allow-Origin": allowed ? origin : ALLOWED_ORIGINS[0],
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}

function reply(req: Request, status: number, body: Record<string, unknown>) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors(req), "Content-Type": "application/json" },
  });
}

const clean = (v: unknown, max: number) =>
  typeof v === "string" ? v.replace(/[\u0000-\u001f\u007f]+/g, " ").trim().slice(0, max) : "";

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

async function sha256(text: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== "POST") return reply(req, 405, { error: "Method not allowed" });

  // Accept JSON or form posts
  let raw: Record<string, unknown> = {};
  try {
    const ct = req.headers.get("content-type") ?? "";
    if (ct.includes("application/json")) {
      raw = await req.json();
    } else {
      const fd = await req.formData();
      for (const key of new Set(fd.keys())) {
        const all = fd.getAll(key).filter((v) => typeof v === "string");
        raw[key] = key === "interest" ? all : all[0];
      }
    }
  } catch {
    return reply(req, 400, { error: "Invalid request" });
  }

  // Honeypot: pretend success so bots learn nothing
  if (clean(raw.website, 200)) return reply(req, 200, { ok: true });

  // Validation
  const name = clean(raw.name, 100);
  const phone = clean(raw.phone, 30);
  const email = clean(raw.email, 254);
  const postcode = clean(raw.postcode, 10).toUpperCase();
  const message = clean(raw.message, 2000);
  const interestsIn = Array.isArray(raw.interest) ? raw.interest : raw.interest ? [raw.interest] : [];
  const interests = [...new Set(interestsIn.map((i) => clean(i, 30)).filter((i) => INTERESTS.includes(i)))];

  if (!name) return reply(req, 400, { error: "Please add your name." });
  if (!/^[0-9+()\-\s]{7,30}$/.test(phone)) return reply(req, 400, { error: "Please add a valid phone number." });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply(req, 400, { error: "That email address doesn't look right." });
  if (postcode && !/^[A-Z0-9 ]{2,10}$/.test(postcode)) return reply(req, 400, { error: "That postcode doesn't look right." });

  const ip = (req.headers.get("cf-connecting-ip") ?? req.headers.get("x-forwarded-for") ?? "unknown")
    .split(",")[0].trim();

  // Turnstile
  const token = clean(raw["cf-turnstile-response"], 2048);
  if (!token) return reply(req, 400, { error: "Please complete the security check." });
  const ts = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: new URLSearchParams({ secret: Deno.env.get("TURNSTILE_SECRET")!, response: token, remoteip: ip }),
  }).then((r) => r.json()).catch(() => null);
  if (!ts?.success) return reply(req, 400, { error: "Security check failed. Please try again." });

  // Rate limit per hashed IP
  const ipHash = await sha256(`${Deno.env.get("IP_HASH_SALT") ?? ""}:${ip}`);
  const since = new Date(Date.now() - RATE_WINDOW_MS).toISOString();
  const { count, error: countErr } = await db.from("enquiries")
    .select("id", { count: "exact", head: true })
    .eq("ip_hash", ipHash).gte("created_at", since);
  if (countErr) { console.error("rate limit lookup failed", countErr.message); return reply(req, 500, { error: "Something went wrong." }); }
  if ((count ?? 0) >= RATE_LIMIT) return reply(req, 429, { error: "Too many enquiries. Please call us instead." });

  const { data: row, error: insErr } = await db.from("enquiries").insert({
    name, phone, email: email || null, postcode: postcode || null, interests,
    message: message || null, ip_hash: ipHash,
    user_agent: clean(req.headers.get("user-agent"), 300) || null,
  }).select("id").single();
  if (insErr) { console.error("insert failed", insErr.message); return reply(req, 500, { error: "Something went wrong." }); }

  // Notify by email; the enquiry is already saved, so a mail failure doesn't fail the request
  const resendKey = Deno.env.get("RESEND_API_KEY");
  const to = Deno.env.get("NOTIFY_TO");
  if (resendKey && to) {
    const html = `<h2>New website enquiry</h2><table cellpadding="6">
      <tr><td><b>Name</b></td><td>${esc(name)}</td></tr>
      <tr><td><b>Phone</b></td><td>${esc(phone)}</td></tr>
      <tr><td><b>Email</b></td><td>${esc(email || "-")}</td></tr>
      <tr><td><b>Postcode</b></td><td>${esc(postcode || "-")}</td></tr>
      <tr><td><b>Interested in</b></td><td>${esc(interests.join(", ") || "-")}</td></tr>
      <tr><td><b>Message</b></td><td>${esc(message || "-").replace(/\n/g, "<br>")}</td></tr></table>`;
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: Deno.env.get("NOTIFY_FROM") ?? "Floors for Living <onboarding@resend.dev>",
        to: [to],
        reply_to: email || undefined,
        subject: `New enquiry from ${name}`,
        html,
      }),
    }).catch(() => null);
    if (res?.ok) await db.from("enquiries").update({ emailed_at: new Date().toISOString() }).eq("id", row.id);
    else console.error("resend failed", res?.status);
  } else {
    console.error("RESEND_API_KEY or NOTIFY_TO not set; enquiry saved without email");
  }

  return reply(req, 200, { ok: true });
});
