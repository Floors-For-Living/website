# Handover: accounts and secrets

Everything the website depends on. Owner = who holds the login and pays/renews.
**Fill in the owner column's names before handing over** (not known from the repo).

| Service | What it does | Where | Owner |
|---|---|---|---|
| Supabase | Database + `enquiry` edge function. Project `gprluocthtaaggxfmjta`. | supabase.com/dashboard | _to confirm_ |
| Resend | Sends the enquiry email from `enquiries@mail.floorsforliving.co.uk` | resend.com | _to confirm_ |
| Cloudflare Turnstile | Spam check on the form (site key is public, in `index.html`) | dash.cloudflare.com | _to confirm_ |
| GitHub | Source code and hosting (`Floors-For-Living/website`, GitHub Pages) | github.com | Floors-For-Living org owner |
| GoDaddy | Domain `floorsforliving.co.uk` and DNS (incl. Resend DKIM/SPF records for `mail.` subdomain) | godaddy.com | _to confirm_ |

## Secrets

Set as Supabase edge function secrets (Project > Edge Functions > Secrets). None are in the repo.

| Secret | Source | Notes |
|---|---|---|
| `RESEND_API_KEY` | Resend > API Keys | Send-only key is enough |
| `NOTIFY_TO` | Chosen address | Where enquiry emails go |
| `TURNSTILE_SECRET` | Cloudflare > Turnstile > widget | Pairs with the public site key in `index.html` |
| `IP_HASH_SALT` | Random (`openssl rand -hex 32`) | Salts the stored IP hash. Changing it just resets rate limits |
| `SUPABASE_DB_URL` | Provided by Supabase automatically | Used for the direct database connection |

Anyone with the Supabase access token can read enquiries. Treat the Supabase login as the master key.

## Data

- Enquiries are stored in the private `enquiries_app` schema, which is not exposed through the Supabase API. Only the edge function (direct DB connection) and logged-in dashboard users can read it.
- Data is stored in Ireland (EEA), Supabase region `eu-west-1`. *(Confirm in Project Settings > General.)*
- A daily pg_cron job (`enquiries_app_retention`) deletes enquiries and rate-limit rows older than 12 months.
- The form sets no cookies and uses no browser storage. Campaign parameters, referrer and landing path are held in memory only and sent with the form.
- Emails also pass through Resend, which is a separate processor and may be outside the EEA; check its DPA settings.

## Deploying

```
supabase db push
supabase functions deploy enquiry --no-verify-jwt
```

## Privacy notice

- Published at `privacy.html` (https://floorsforliving.co.uk/privacy.html), linked from the site footer and the enquiry form.
- Current version: `privacy-2026-10-26`. The same string is `CONSENT_VERSION` in `index.html` and is stored with every enquiry as `consent_version`.
- **The notice and `CONSENT_VERSION` must be updated together whenever data collection or processors change.** Change the "Last updated" date, the version comment in `privacy.html` and `CONSENT_VERSION`, and add the date to `sitemap.xml`.
- Processors named in the notice: Supabase (database, Ireland), Resend (enquiry emails), Cloudflare (Turnstile spam check), GitHub (hosting), GoDaddy (domain and email). Google Maps and Google Fonts are also loaded by the site.
- Still to fill in `privacy.html`: legal business name and ICO registration number (highlighted in yellow, with TODO comments).
