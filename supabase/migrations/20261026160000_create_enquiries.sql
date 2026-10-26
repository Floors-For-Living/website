-- Website enquiry form submissions. Written only by the `enquiry` edge function
-- (service role); RLS is on with no policies, so anon/authenticated get nothing.
create table if not exists public.enquiries (
  id          uuid primary key default gen_random_uuid(),
  created_at  timestamptz not null default now(),
  name        text not null check (char_length(name) between 1 and 100),
  phone       text not null check (char_length(phone) between 5 and 30),
  email       text check (email is null or char_length(email) <= 254),
  postcode    text check (postcode is null or char_length(postcode) <= 10),
  interests   text[] not null default '{}',
  message     text check (message is null or char_length(message) <= 2000),
  ip_hash     text,
  user_agent  text,
  emailed_at  timestamptz
);

create index if not exists enquiries_ip_hash_created_at_idx
  on public.enquiries (ip_hash, created_at desc);

alter table public.enquiries enable row level security;
revoke all on public.enquiries from anon, authenticated;
