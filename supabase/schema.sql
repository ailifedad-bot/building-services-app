-- Phase 2A: central database foundation for Building Services Gorgan
-- Run in Supabase SQL Editor on a NEW project. Review before production use.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  phone text unique not null,
  role text not null default 'customer' check (role in ('customer','technician','admin')),
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.technician_profiles (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  specialty text not null check (specialty in ('برق ساختمان','لوله‌کشی و تأسیسات','فاضلاب و تخلیه','چند تخصص')),
  home_area text not null,
  service_areas text[] not null default '{}',
  coverage text not null default 'selected' check (coverage in ('selected','city')),
  latitude double precision,
  longitude double precision,
  approved boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((latitude is null and longitude is null) or
         (latitude between -90 and 90 and longitude between -180 and 180))
);

create table if not exists public.service_requests (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id),
  technician_id uuid references public.technician_profiles(user_id),
  service_type text not null check (service_type in ('برق ساختمان','لوله‌کشی و تأسیسات','فاضلاب و تخلیه')),
  problem_type text not null,
  area text not null,
  address text,
  description text not null,
  latitude double precision,
  longitude double precision,
  status text not null default 'submitted'
    check (status in ('submitted','referred','in_progress','rejected','completed','cancelled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((latitude is null and longitude is null) or
         (latitude between -90 and 90 and longitude between -180 and 180))
);

create index if not exists service_requests_customer_idx on public.service_requests(customer_id, created_at desc);
create index if not exists service_requests_technician_idx on public.service_requests(technician_id, status);
create index if not exists technician_profiles_areas_gin on public.technician_profiles using gin(service_areas);

create table if not exists public.technician_ratings (
  id uuid primary key default gen_random_uuid(),
  request_id uuid not null unique references public.service_requests(id) on delete cascade,
  customer_id uuid not null references public.profiles(id),
  technician_id uuid not null references public.technician_profiles(user_id),
  score integer not null check (score between 1 and 5),
  comment text,
  created_at timestamptz not null default now()
);

create table if not exists public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id),
  account_group text not null check (account_group in ('customer','technician')),
  plan text not null check (plan in ('ten_day','monthly')),
  amount_toman bigint not null check (amount_toman >= 0),
  status text not null default 'pending' check (status in ('pending','paid','expired','cancelled')),
  starts_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

-- Create a customer profile automatically after verified Supabase Auth signup.
create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, phone, role)
  values (new.id, coalesce(new.phone, ''), 'customer')
  on conflict (id) do update set phone = excluded.phone;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile
after insert on auth.users
for each row execute procedure public.handle_new_auth_user();

-- Never allow a browser client to promote itself or approve a technician.
create or replace function public.protect_privileged_fields()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if auth.role() <> 'service_role' then
    if tg_table_name = 'profiles' and new.role is distinct from old.role then
      raise exception 'Role changes require administrator action';
    end if;
    if tg_table_name = 'technician_profiles' and new.approved is distinct from old.approved then
      raise exception 'Technician approval requires administrator action';
    end if;
  end if;
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists protect_profile_role on public.profiles;
create trigger protect_profile_role before update on public.profiles
for each row execute procedure public.protect_privileged_fields();

drop trigger if exists protect_technician_approval on public.technician_profiles;
create trigger protect_technician_approval before update on public.technician_profiles
for each row execute procedure public.protect_privileged_fields();

create or replace function public.touch_request_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at = now(); return new; end; $$;
drop trigger if exists touch_service_request on public.service_requests;
create trigger touch_service_request before update on public.service_requests
for each row execute procedure public.touch_request_updated_at();

alter table public.profiles enable row level security;
alter table public.technician_profiles enable row level security;
alter table public.service_requests enable row level security;
alter table public.technician_ratings enable row level security;
alter table public.subscriptions enable row level security;

-- Profiles: users can read/update only their own profile. Admin policies are added
-- after an administrator is assigned securely in the Supabase SQL editor.
drop policy if exists "profile read self" on public.profiles;
create policy "profile read self" on public.profiles for select to authenticated
using (id = (select auth.uid()));
drop policy if exists "profile update self" on public.profiles;
create policy "profile update self" on public.profiles for update to authenticated
using (id = (select auth.uid())) with check (id = (select auth.uid()));

-- Approved technicians are discoverable; each technician manages only their own record.
drop policy if exists "technician profiles public read approved" on public.technician_profiles;
create policy "technician profiles public read approved" on public.technician_profiles
for select to authenticated using (approved = true or user_id = (select auth.uid()));
drop policy if exists "technician profile insert self" on public.technician_profiles;
create policy "technician profile insert self" on public.technician_profiles
for insert to authenticated with check (
  user_id = (select auth.uid()) and
  exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.role = 'technician')
);
drop policy if exists "technician profile update self" on public.technician_profiles;
create policy "technician profile update self" on public.technician_profiles
for update to authenticated using (user_id = (select auth.uid()))
with check (user_id = (select auth.uid()));

-- Requests: customer creates and reads own; assigned technician reads and updates assigned work.
drop policy if exists "customer creates own requests" on public.service_requests;
create policy "customer creates own requests" on public.service_requests
for insert to authenticated with check (
  customer_id = (select auth.uid()) and status = 'submitted'
);
drop policy if exists "request visible to customer or assigned tech" on public.service_requests;
create policy "request visible to customer or assigned tech" on public.service_requests
for select to authenticated using (
  customer_id = (select auth.uid()) or technician_id = (select auth.uid())
);
drop policy if exists "assigned technician updates request" on public.service_requests;
create policy "assigned technician updates request" on public.service_requests
for update to authenticated
using (technician_id = (select auth.uid()) and status in ('referred','in_progress'))
with check (technician_id = (select auth.uid()) and status in ('referred','in_progress','rejected','completed'));

-- Ratings: customers can rate only their own completed request, once.
drop policy if exists "ratings visible to signed in users" on public.technician_ratings;
create policy "ratings visible to signed in users" on public.technician_ratings
for select to authenticated using (true);
drop policy if exists "customer rates completed request" on public.technician_ratings;
create policy "customer rates completed request" on public.technician_ratings
for insert to authenticated with check (
  customer_id = (select auth.uid()) and
  exists (
    select 1 from public.service_requests r
    where r.id = request_id and r.customer_id = (select auth.uid())
      and r.technician_id = technician_id and r.status = 'completed'
  )
);

-- Subscription requests are private to their owner; payment activation is server-side only.
drop policy if exists "users read own subscriptions" on public.subscriptions;
create policy "users read own subscriptions" on public.subscriptions
for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "users create own pending subscriptions" on public.subscriptions;
create policy "users create own pending subscriptions" on public.subscriptions
for insert to authenticated with check (
  user_id = (select auth.uid()) and status = 'pending'
);

-- Public aggregate view does not expose phone numbers or private technician data.
create or replace view public.technician_rating_summary
with (security_invoker = true) as
select technician_id,
       round(avg(score)::numeric, 2) as average_score,
       count(*)::integer as rating_count
from public.technician_ratings
group by technician_id;

grant select on public.technician_rating_summary to authenticated;
