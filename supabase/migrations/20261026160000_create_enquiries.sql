-- Website enquiries live in a private schema that is NOT in the API's exposed
-- schemas (PostgREST only serves `public`/`graphql_public`). The `enquiry` edge
-- function reaches it over a direct database connection; nothing else can.
-- RLS is on with no policies, and all API roles are locked out as well.
create schema if not exists enquiries_app;
revoke all on schema enquiries_app from public, anon, authenticated;

create or replace function enquiries_app.gen_ref() returns text
language plpgsql as $$
declare candidate text;
begin
  loop
    -- "FFL-" plus 4 to 6 digits, no leading zero so the length is meaningful
    candidate := 'FFL-' || (1000 + floor(random() * 999000))::int::text;
    exit when not exists (select 1 from enquiries_app.enquiries where ref = candidate);
  end loop;
  return candidate;
end $$;

create table if not exists enquiries_app.enquiries (
  id                   uuid primary key default gen_random_uuid(),
  ref                  text not null unique default enquiries_app.gen_ref()
                         check (ref ~ '^FFL-[0-9]{4,6}$'),
  first_name           text not null check (char_length(first_name) between 1 and 100),
  phone                text not null check (char_length(phone) between 5 and 30),
  email                text check (email is null or char_length(email) <= 254),
  message              text not null default '' check (char_length(message) <= 2000),
  consent_version      text not null,
  utm_source           text,
  utm_medium           text,
  utm_campaign         text,
  utm_content          text,
  utm_term             text,
  fbclid               text,
  gclid                text,
  referrer             text,
  landing_path         text,
  self_reported_source text,
  created_at           timestamptz not null default now()
);

-- Per-IP rate limiting (hashed IP only)
create table if not exists enquiries_app.rate_limits (
  id         bigint generated always as identity primary key,
  ip_hash    text not null,
  created_at timestamptz not null default now()
);
create index if not exists rate_limits_ip_hash_created_at_idx
  on enquiries_app.rate_limits (ip_hash, created_at desc);

alter table enquiries_app.enquiries   enable row level security;
alter table enquiries_app.rate_limits enable row level security;
revoke all on all tables    in schema enquiries_app from public, anon, authenticated;
revoke all on all sequences in schema enquiries_app from public, anon, authenticated;
revoke all on all functions in schema enquiries_app from public, anon, authenticated;

-- Retention: delete anything older than 12 months, daily at 03:17 UTC
create extension if not exists pg_cron;
select cron.unschedule(jobid) from cron.job where jobname = 'enquiries_app_retention';
select cron.schedule('enquiries_app_retention', '17 3 * * *', $job$
  delete from enquiries_app.enquiries   where created_at < now() - interval '12 months';
  delete from enquiries_app.rate_limits where created_at < now() - interval '12 months';
$job$);
