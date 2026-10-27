import postgres from "npm:postgres@3";

const ALLOWED_ORIGINS = [
  "https://floorsforliving.co.uk",
  "https://www.floorsforliving.co.uk",
  "https://floors-for-living.github.io",
];
const FROM = "Floors for Living <enquiries@mail.floorsforliving.co.uk>";
const PHONE = "01833 695875";
const INTERESTS = ["Carpet", "LVT", "Vinyl", "Real wood", "Bespoke", "Accessories", "Not sure yet"];
const SOURCES = [
  "Google search", "Facebook or Instagram", "Friend or family", "Passed the shop",
  "Leaflet or newspaper", "Returning customer", "Other",
];
const RATE_LIMIT = 5; // submissions per IP per window
const RATE_WINDOW_MINUTES = 60;

// Direct connection: the enquiries_app schema is deliberately not exposed through the API.
const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { max: 1, prepare: false });

const isLocal = (o: string) => /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(o);
const originAllowed = (o: string) => ALLOWED_ORIGINS.includes(o) || isLocal(o);

function cors(req: Request) {
  const origin = req.headers.get("origin") ?? "";
  return {
    "Access-Control-Allow-Origin": originAllowed(origin) ? origin : ALLOWED_ORIGINS[0],
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

function hostOf(url: string) {
  try { return new URL(url).hostname; } catch { return ""; }
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin") ?? "";
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
  if (req.method !== "POST") return reply(req, 405, { error: "Method not allowed" });
  if (origin && !originAllowed(origin)) return reply(req, 403, { error: "Origin not allowed" });

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
  const firstName = clean(raw.first_name, 100);
  const phone = clean(raw.phone, 30);
  const email = clean(raw.email, 254);
  const postcode = clean(raw.postcode, 10).toUpperCase();
  const freeText = String(typeof raw.message === "string" ? raw.message : "").replace(/\r\n/g, "\n")
    .replace(/[\u0000-\u0009\u000b-\u001f\u007f]+/g, " ").trim().slice(0, 1500);
  const interestsIn = Array.isArray(raw.interest) ? raw.interest : raw.interest ? [raw.interest] : [];
  const interests = [...new Set(interestsIn.map((i) => clean(i, 30)).filter((i) => INTERESTS.includes(i)))];
  const consentVersion = clean(raw.consent_version, 40);
  const selfReported = clean(raw.self_reported_source, 60);

  if (!firstName) return reply(req, 400, { error: "Please add your name." });
  if (!/^[0-9+()\-\s]{7,30}$/.test(phone)) return reply(req, 400, { error: "Please add a valid phone number." });
  if (!email) return reply(req, 400, { error: "Please add your email address." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return reply(req, 400, { error: "That email address doesn't look right." });
  if (postcode && !/^[A-Z0-9 ]{2,10}$/.test(postcode)) return reply(req, 400, { error: "That postcode doesn't look right." });
  if (!consentVersion) return reply(req, 400, { error: "Missing consent version." });
  if (selfReported && !SOURCES.includes(selfReported)) return reply(req, 400, { error: "Invalid source." });

  // The spec has no postcode/interest columns, so fold them into the message
  const message = [
    interests.length ? `Interested in: ${interests.join(", ")}` : "",
    postcode ? `Postcode: ${postcode}` : "",
    freeText,
  ].filter(Boolean).join("\n").slice(0, 2000);

  const attribution = {
    utm_source: clean(raw.utm_source, 200) || null,
    utm_medium: clean(raw.utm_medium, 200) || null,
    utm_campaign: clean(raw.utm_campaign, 200) || null,
    utm_content: clean(raw.utm_content, 200) || null,
    utm_term: clean(raw.utm_term, 200) || null,
    fbclid: clean(raw.fbclid, 500) || null,
    gclid: clean(raw.gclid, 500) || null,
    referrer: clean(raw.referrer, 500) || null,
    landing_path: clean(raw.landing_path, 300) || null,
  };

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

  // Rate limit per hashed IP (attempts that pass Turnstile are recorded)
  const ipHash = await sha256(`${Deno.env.get("IP_HASH_SALT") ?? ""}:${ip}`);
  let ref = "";
  try {
    const [{ n }] = await sql`
      select count(*)::int as n from enquiries_app.rate_limits
      where ip_hash = ${ipHash} and created_at > now() - make_interval(mins => ${RATE_WINDOW_MINUTES})`;
    if (n >= RATE_LIMIT) return reply(req, 429, { error: `Too many enquiries. Please call us on ${PHONE}.` });
    await sql`insert into enquiries_app.rate_limits (ip_hash) values (${ipHash})`;

    // ref is generated server-side by the column default; retry on the rare unique collision
    for (let attempt = 0; attempt < 5 && !ref; attempt++) {
      try {
        const [row] = await sql`
          insert into enquiries_app.enquiries
            (first_name, phone, email, message, consent_version, utm_source, utm_medium, utm_campaign,
             utm_content, utm_term, fbclid, gclid, referrer, landing_path, self_reported_source)
          values
            (${firstName}, ${phone}, ${email || null}, ${message}, ${consentVersion},
             ${attribution.utm_source}, ${attribution.utm_medium}, ${attribution.utm_campaign},
             ${attribution.utm_content}, ${attribution.utm_term}, ${attribution.fbclid}, ${attribution.gclid},
             ${attribution.referrer}, ${attribution.landing_path}, ${selfReported || null})
          returning ref`;
        ref = row.ref;
      } catch (e) {
        if ((e as { code?: string }).code !== "23505") throw e;
      }
    }
    if (!ref) throw new Error("could not allocate ref");
  } catch (e) {
    console.error("database error", (e as { code?: string }).code ?? "unknown");
    return reply(req, 500, { error: `Something went wrong. Please call us on ${PHONE}.` });
  }

  // Notify by email; the enquiry is already saved, so a mail failure doesn't fail the request
  const resendKey = Deno.env.get("RESEND_API_KEY");
  const to = Deno.env.get("NOTIFY_TO");
  if (resendKey && to) {
    const source = attribution.utm_source || selfReported || hostOf(attribution.referrer ?? "") || "direct";
    const campaign = attribution.utm_campaign || "none";
    const telHref = phone.replace(/[^0-9+]/g, "");
    const messageHtml = esc(message || "No message").replace(/\n/g, "<br>");
    const extras: [string, string | null][] = [
      ["Medium", attribution.utm_medium],
      ["Content", attribution.utm_content],
      ["Term", attribution.utm_term],
      ["Referrer", attribution.referrer],
      ["Landing page", attribution.landing_path],
      ["Facebook click ID", attribution.fbclid],
      ["Google click ID", attribution.gclid],
    ];
    const extraRows = extras
      .filter(([, v]) => v)
      .map(([k, v]) => `<tr><td style="padding:3px 14px 3px 0;color:#8a8479;font-size:13px;white-space:nowrap;vertical-align:top">${k}</td><td style="padding:3px 0;color:#3a362f;font-size:13px;word-break:break-all">${esc(v as string)}</td></tr>`)
      .join("");
    const html = `<!doctype html><html><body style="margin:0;padding:0;background:#eceae5">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">${esc(firstName)}, ${esc(phone)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#eceae5"><tr><td align="center" style="padding:24px 12px">
 <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;font-family:Helvetica,Arial,sans-serif">
  <tr><td style="background:#0e0d0b;padding:22px 28px;border-bottom:3px solid #b8924a">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="color:#ecdc94;font-size:13px;letter-spacing:3px;font-weight:bold">FLOORS FOR LIVING</td>
      <td align="right" style="color:#a9a297;font-size:12px;letter-spacing:2px">${esc(ref)}</td>
    </tr></table>
  </td></tr>
  <tr><td style="background:#ffffff;padding:28px">
    <p style="margin:0 0 4px;color:#8f6a2c;font-size:12px;letter-spacing:2px;font-weight:bold">NEW ENQUIRY</p>
    <h1 style="margin:0 0 20px;font-size:28px;line-height:1.2;color:#0e0d0b">${esc(firstName)}</h1>
    <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 18px"><tr><td style="background:#b8924a;border-radius:2px">
      <a href="tel:${telHref}" style="display:inline-block;padding:14px 22px;color:#0e0d0b;font-size:17px;font-weight:bold;text-decoration:none">Call ${esc(phone)}</a>
    </td></tr></table>
    <p style="margin:0 0 20px;font-size:15px;color:#3a362f">Email: <a href="mailto:${esc(email)}" style="color:#8f6a2c">${esc(email)}</a></p>
    <div style="background:#f8f7f4;border-left:3px solid #b8924a;padding:14px 16px;font-size:15px;line-height:1.6;color:#1c1a17">${messageHtml}</div>
    <p style="margin:18px 0 0;font-size:13px;color:#8a8479">Hit reply to answer ${esc(firstName)} by email.</p>
  </td></tr>
  <tr><td style="background:#ffffff;padding:0 28px 24px">
    <div style="border-top:1px solid #e3dfd6;padding-top:16px">
      <p style="margin:0 0 8px;color:#8f6a2c;font-size:12px;letter-spacing:2px;font-weight:bold">WHERE IT CAME FROM</p>
      <p style="margin:0 0 8px;font-size:15px;color:#1c1a17"><b>${esc(source)}</b> &middot; campaign: ${esc(campaign)}</p>
      <table role="presentation" cellpadding="0" cellspacing="0">${extraRows}</table>
    </div>
  </td></tr>
  <tr><td style="padding:14px 4px;color:#8a8479;font-size:12px">Ref ${esc(ref)} &middot; Notice version ${esc(consentVersion)}</td></tr>
 </table>
</td></tr></table></body></html>`;
    const text = [
      `New website enquiry ${ref}`,
      ``,
      `Name: ${firstName}`,
      `Phone: ${phone}`,
      `Email: ${email}`,
      ``,
      message || "No message",
      ``,
      `Source: ${source}`,
      `Campaign: ${campaign}`,
    ].join("\n");
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: `Bearer ${resendKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: FROM,
        to: to.split(",").map((s) => s.trim()).filter(Boolean),
        reply_to: email || undefined,
        subject: `New enquiry ${ref} from ${firstName}`,
        html,
        text,
      }),
    }).catch(() => null);
    if (!res?.ok) console.error("resend failed", res?.status);
  } else {
    console.error("RESEND_API_KEY or NOTIFY_TO not set; enquiry saved without email");
  }

  return reply(req, 200, { ok: true, ref });
});
