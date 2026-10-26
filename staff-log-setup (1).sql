-- KMDS Staff Activity log: one-time setup. Paste into Supabase > SQL Editor > Run.
create table if not exists public.staff_sessions (
  id uuid primary key,
  user_id uuid not null default auth.uid(),
  email text,
  name text,
  login_at timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  logout_at timestamptz
);
alter table public.staff_sessions enable row level security;

drop policy if exists staff_ins on public.staff_sessions;
create policy staff_ins on public.staff_sessions for insert to authenticated
  with check (user_id = auth.uid());

drop policy if exists staff_upd on public.staff_sessions;
create policy staff_upd on public.staff_sessions for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- Owner sees everyone; every other staff member sees only their own rows.
-- If your portal login email is not the one below, change it here.
drop policy if exists staff_sel on public.staff_sessions;
create policy staff_sel on public.staff_sessions for select to authenticated
  using (user_id = auth.uid() or (auth.jwt() ->> 'email') = 'sergeikome003@gmail.com');

-- No delete policy on purpose: nobody can delete records from the portal.

-- Tamper protection: times are stamped by the server, not the browser.
create or replace function public.staff_sessions_before_ins() returns trigger as $$
begin
  new.user_id := auth.uid();
  new.email := auth.jwt() ->> 'email';
  new.login_at := now();
  new.last_seen := now();
  new.logout_at := null;
  return new;
end $$ language plpgsql security definer set search_path = public;
drop trigger if exists staff_before_ins on public.staff_sessions;
create trigger staff_before_ins before insert on public.staff_sessions
  for each row execute function public.staff_sessions_before_ins();

create or replace function public.staff_sessions_before_upd() returns trigger as $$
begin
  new.id := old.id; new.user_id := old.user_id; new.email := old.email;
  new.name := old.name; new.login_at := old.login_at;
  new.last_seen := now();
  if old.logout_at is not null then new.logout_at := old.logout_at;
  elsif new.logout_at is not null then new.logout_at := now(); end if;
  return new;
end $$ language plpgsql security definer set search_path = public;
drop trigger if exists staff_before_upd on public.staff_sessions;
create trigger staff_before_upd before update on public.staff_sessions
  for each row execute function public.staff_sessions_before_upd();
