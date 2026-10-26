-- Cookieless, anonymous page-view and CTA-click counts for zelsis.com (no IP, no user agent, no identifier stored).
-- Only the server (service role) reads or writes this table: RLS is on and there are no policies.
create table if not exists public.site_events (
  day date not null default ((now() at time zone 'utc')::date),
  kind text not null check (kind in ('view', 'cta')),
  path text not null,
  source text not null default '',
  label text not null default '',
  count integer not null default 0,
  primary key (day, kind, path, source, label)
);

alter table public.site_events enable row level security;

-- One increment per event. A day holds at most 2000 distinct rows: past that, new combinations are counted under
-- '/other', so the endpoint cannot be used to grow the table.
create or replace function public.bump_site_event(p_kind text, p_path text, p_source text, p_label text)
returns void
language plpgsql
set search_path = public
as $$
declare
  today date := (now() at time zone 'utc')::date;
begin
  if not exists (
    select 1 from public.site_events
    where day = today and kind = p_kind and path = p_path and source = p_source and label = p_label
  ) and (select count(*) from public.site_events where day = today) >= 2000 then
    p_path := '/other';
    p_source := 'other';
    p_label := '';
  end if;

  insert into public.site_events (day, kind, path, source, label, count)
  values (today, p_kind, p_path, p_source, p_label, 1)
  on conflict (day, kind, path, source, label) do update set count = public.site_events.count + 1;
end;
$$;

revoke all on function public.bump_site_event(text, text, text, text) from public, anon, authenticated;
grant execute on function public.bump_site_event(text, text, text, text) to service_role;
