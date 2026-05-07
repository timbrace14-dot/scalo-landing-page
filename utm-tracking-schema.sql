-- ============================================================
-- SCALO UTM PAGEVIEW TRACKING — Supabase schema
-- ============================================================
-- Run this in the Supabase SQL Editor for your project at
-- https://kadgzthwuzzjwxxcbgzi.supabase.co
--
-- Creates a single new table `utm_clicks` to track every visit
-- to join.buildwithscalo.com (anonymous pageviews, not just opt-ins).
-- The existing `leads` table is left untouched.
-- ============================================================

create table if not exists public.utm_clicks (
  id            bigserial primary key,
  visited_at    timestamptz not null default now(),
  utm_source    text,
  utm_medium    text,
  utm_campaign  text,
  utm_content   text,
  visitor_id    text,
  referrer      text,
  landing_path  text,
  user_agent    text,
  device        text,
  is_bot        boolean default false
);

create index if not exists utm_clicks_visited_at_idx
  on public.utm_clicks (visited_at desc);

create index if not exists utm_clicks_source_idx
  on public.utm_clicks (utm_source, utm_medium);

create index if not exists utm_clicks_visitor_idx
  on public.utm_clicks (visitor_id);

-- Row Level Security: anon can insert, authenticated can read
alter table public.utm_clicks enable row level security;

drop policy if exists "anon insert pageviews" on public.utm_clicks;
create policy "anon insert pageviews"
  on public.utm_clicks
  for insert
  to anon
  with check (true);

drop policy if exists "authenticated read pageviews" on public.utm_clicks;
create policy "authenticated read pageviews"
  on public.utm_clicks
  for select
  to authenticated
  using (true);

-- Allow the anon role used by the BOS dashboard to read too,
-- since the BOS uses the anon key (not a logged-in Supabase user).
drop policy if exists "anon read pageviews" on public.utm_clicks;
create policy "anon read pageviews"
  on public.utm_clicks
  for select
  to anon
  using (true);
