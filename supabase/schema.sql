-- Clean baseline schema for Building Services Gorgan.
-- Non-destructive: no tables or records are dropped.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 phone text not null unique,
 role text not null default 'customer' check (role in ('customer','technician','admin')),
 full_name text,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);

create table if not exists public.service_areas (
 id text primary key,
 name text not null unique,
 active boolean not null default true,
 sort_order integer not null default 0
);

create table if not exists public.technician_profiles (
 user_id uuid primary key references public.profiles(id) on delete cascade,
 specialty text not null,
 home_area_id text not null references public.service_areas(id),
 service_area_ids text[] not null default '{}',
 serves_all_areas boolean not null default false,
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
 service_type text not null,
 problem_type text not null,
 area_id text not null references public.service_areas(id),
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

create table if not exists public.request_events (
 id bigint generated always as identity primary key,
 request_id uuid not null references public.service_requests(id) on delete cascade,
 actor_id uuid references public.profiles(id),
 old_status text,
 new_status text not null,
 note text,
 created_at timestamptz not null default now()
);

create table if not exists public.technician_ratings (
 id uuid primary key default gen_random_uuid(),
 request_id uuid not null unique references public.service_requests(id) on delete cascade,
 customer_id uuid not null references public.profiles(id),
 technician_id uuid not null references public.technician_profiles(user_id),
 score integer not null check (score between 1 and 5),
 comment text,
 created_at timestamptz not null default now()
);

create table if not exists public.subscription_plans (
 account_type text not null check (account_type in ('customer','technician')),
 plan_code text not null check (plan_code in ('ten_day','monthly')),
 title text not null,
 price_toman bigint not null check (price_toman >= 0),
 duration_days integer not null check (duration_days in (10,30)),
 active boolean not null default true,
 primary key (account_type, plan_code)
);

create table if not exists public.subscriptions (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references public.profiles(id),
 account_type text not null,
 plan_code text not null,
 price_toman bigint not null check (price_toman >= 0),
 status text not null default 'pending' check (status in ('pending','paid','expired','cancelled')),
 starts_at timestamptz,
 expires_at timestamptz,
 created_at timestamptz not null default now(),
 foreign key (account_type, plan_code)
  references public.subscription_plans(account_type, plan_code)
);

create index if not exists req_customer_date_idx on public.service_requests(customer_id, created_at desc);
create index if not exists req_technician_status_idx on public.service_requests(technician_id, status);
create index if not exists technician_areas_gin_idx on public.technician_profiles using gin(service_area_ids);
create index if not exists req_events_request_idx on public.request_events(request_id, created_at);

-- New users may choose customer or technician; admin is never self-selectable.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
declare chosen_role text;
begin
 chosen_role := case when new.raw_user_meta_data ->> 'account_type' = 'technician'
  then 'technician' else 'customer' end;
 insert into public.profiles(id, phone, role)
 values (new.id, coalesce(new.phone,''), chosen_role)
 on conflict (id) do nothing;
 return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = ''
as $$
 select exists(select 1 from public.profiles p
  where p.id = (select auth.uid()) and p.role = 'admin');
$$;

create or replace function public.protect_profile_role()
returns trigger language plpgsql set search_path = ''
as $$
begin
 if new.role is distinct from old.role and not public.is_admin()
  and current_user not in ('postgres','supabase_admin') then
  raise exception 'Only an administrator can change account role';
 end if;
 new.updated_at := now();
 return new;
end;
$$;
drop trigger if exists protect_profile_role on public.profiles;
create trigger protect_profile_role before update on public.profiles
for each row execute procedure public.protect_profile_role();

create or replace function public.protect_technician_approval()
returns trigger language plpgsql set search_path = ''
as $$
begin
 if new.approved is distinct from old.approved and not public.is_admin()
  and current_user not in ('postgres','supabase_admin') then
  raise exception 'Only an administrator can approve technicians';
 end if;
 new.updated_at := now();
 return new;
end;
$$;
drop trigger if exists protect_technician_approval on public.technician_profiles;
create trigger protect_technician_approval before update on public.technician_profiles
for each row execute procedure public.protect_technician_approval();

create or replace function public.touch_updated_at()
returns trigger language plpgsql set search_path = ''
as $$ begin new.updated_at := now(); return new; end; $$;
drop trigger if exists touch_technician_updated_at on public.technician_profiles;
create trigger touch_technician_updated_at before update on public.technician_profiles
for each row execute procedure public.touch_updated_at();
drop trigger if exists touch_request_updated_at on public.service_requests;
create trigger touch_request_updated_at before update on public.service_requests
for each row execute procedure public.touch_updated_at();

create or replace function public.log_request_status_change()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
 if new.status is distinct from old.status then
  insert into public.request_events(request_id,actor_id,old_status,new_status)
  values(new.id,auth.uid(),old.status,new.status);
 end if;
 return new;
end;
$$;
drop trigger if exists log_request_status on public.service_requests;
create trigger log_request_status after update of status on public.service_requests
for each row execute procedure public.log_request_status_change();

-- Create a request only after validating the customer's chosen technician.
create or replace function public.create_service_request(
 p_service_type text, p_problem_type text, p_area_id text, p_description text,
 p_technician_id uuid default null, p_address text default null,
 p_latitude double precision default null, p_longitude double precision default null
) returns uuid language plpgsql security definer set search_path = ''
as $$
declare new_id uuid; new_status text := 'submitted';
begin
 if auth.uid() is null then raise exception 'Authentication required'; end if;
 if not exists(select 1 from public.service_areas a where a.id=p_area_id and a.active) then
  raise exception 'Invalid or inactive service area';
 end if;
 if p_technician_id is not null then
  if not exists(select 1 from public.technician_profiles t
   where t.user_id=p_technician_id and t.approved
    and (t.specialty=p_service_type or t.specialty='چند تخصص')
    and (t.serves_all_areas or p_area_id=t.home_area_id or p_area_id=any(t.service_area_ids))) then
   raise exception 'Technician is not approved for this service area or specialty';
  end if;
  new_status := 'referred';
 end if;
 insert into public.service_requests(customer_id,technician_id,service_type,problem_type,
  area_id,description,address,latitude,longitude,status)
 values(auth.uid(),p_technician_id,p_service_type,p_problem_type,p_area_id,
  p_description,p_address,p_latitude,p_longitude,new_status)
 returning id into new_id;
 return new_id;
end;
$$;

create or replace function public.reassign_service_request(p_request_id uuid,p_technician_id uuid)
returns void language plpgsql security definer set search_path = ''
as $$
declare req public.service_requests%rowtype;
begin
 if auth.uid() is null then raise exception 'Authentication required'; end if;
 select * into req from public.service_requests
  where id=p_request_id and customer_id=auth.uid() for update;
 if not found or req.status <> 'rejected' then raise exception 'Request is not available for reassignment'; end if;
 if not exists(select 1 from public.technician_profiles t
  where t.user_id=p_technician_id and t.approved
   and (t.specialty=req.service_type or t.specialty='چند تخصص')
   and (t.serves_all_areas or req.area_id=t.home_area_id or req.area_id=any(t.service_area_ids))) then
  raise exception 'Technician is not approved for this service area or specialty';
 end if;
 update public.service_requests set technician_id=p_technician_id,status='referred'
  where id=p_request_id;
end;
$$;

create or replace function public.update_request_status(p_request_id uuid,p_new_status text,p_note text default null)
returns void language plpgsql security definer set search_path = ''
as $$
declare req public.service_requests%rowtype;
begin
 if auth.uid() is null then raise exception 'Authentication required'; end if;
 select * into req from public.service_requests
  where id=p_request_id and technician_id=auth.uid() for update;
 if not found then raise exception 'Request not assigned to this technician'; end if;
 if not ((req.status='referred' and p_new_status in ('in_progress','rejected'))
  or (req.status='in_progress' and p_new_status='completed')) then
  raise exception 'Invalid status transition';
 end if;
 update public.service_requests set status=p_new_status where id=p_request_id;
 if p_note is not null then
  insert into public.request_events(request_id,actor_id,old_status,new_status,note)
  values(p_request_id,auth.uid(),req.status,p_new_status,p_note);
 end if;
end;
$$;

create or replace function public.request_subscription(p_plan_code text)
returns uuid language plpgsql security definer set search_path = ''
as $$
declare user_role text; plan_row public.subscription_plans%rowtype; new_id uuid;
begin
 if auth.uid() is null then raise exception 'Authentication required'; end if;
 select role into user_role from public.profiles where id=auth.uid();
 if user_role not in ('customer','technician') then raise exception 'Invalid account type'; end if;
 select * into plan_row from public.subscription_plans
  where account_type=user_role and plan_code=p_plan_code and active;
 if not found then raise exception 'Subscription plan is not configured'; end if;
 insert into public.subscriptions(user_id,account_type,plan_code,price_toman,status)
 values(auth.uid(),user_role,plan_row.plan_code,plan_row.price_toman,'pending')
 returning id into new_id;
 return new_id;
end;
$$;

create or replace view public.technician_rating_summary with (security_invoker=true) as
select technician_id,round(avg(score)::numeric,2) average_score,count(*)::integer rating_count
from public.technician_ratings group by technician_id;

alter table public.profiles enable row level security;
alter table public.service_areas enable row level security;
alter table public.technician_profiles enable row level security;
alter table public.service_requests enable row level security;
alter table public.request_events enable row level security;
alter table public.technician_ratings enable row level security;
alter table public.subscription_plans enable row level security;
alter table public.subscriptions enable row level security;

drop policy if exists profiles_read_self on public.profiles;
create policy profiles_read_self on public.profiles for select to authenticated
using(id=auth.uid() or public.is_admin());
drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles for update to authenticated
using(id=auth.uid() or public.is_admin()) with check(id=auth.uid() or public.is_admin());
revoke update on public.profiles from authenticated;
grant update(full_name) on public.profiles to authenticated;

drop policy if exists areas_read_active on public.service_areas;
create policy areas_read_active on public.service_areas for select to authenticated
using(active or public.is_admin());
drop policy if exists areas_admin_manage on public.service_areas;
create policy areas_admin_manage on public.service_areas for all to authenticated
using(public.is_admin()) with check(public.is_admin());

drop policy if exists technicians_read_approved on public.technician_profiles;
create policy technicians_read_approved on public.technician_profiles for select to authenticated
using(approved or user_id=auth.uid() or public.is_admin());
drop policy if exists technicians_insert_self on public.technician_profiles;
create policy technicians_insert_self on public.technician_profiles for insert to authenticated
with check(user_id=auth.uid() and exists(select 1 from public.profiles p where p.id=auth.uid() and p.role='technician'));
drop policy if exists technicians_update_self on public.technician_profiles;
create policy technicians_update_self on public.technician_profiles for update to authenticated
using(user_id=auth.uid() or public.is_admin()) with check(user_id=auth.uid() or public.is_admin());
revoke update on public.technician_profiles from authenticated;
grant update(specialty,home_area_id,service_area_ids,serves_all_areas,latitude,longitude) on public.technician_profiles to authenticated;

drop policy if exists requests_read_participants on public.service_requests;
create policy requests_read_participants on public.service_requests for select to authenticated
using(customer_id=auth.uid() or technician_id=auth.uid() or public.is_admin());

drop policy if exists events_read_participants on public.request_events;
create policy events_read_participants on public.request_events for select to authenticated
using(exists(select 1 from public.service_requests r where r.id=request_id
 and (r.customer_id=auth.uid() or r.technician_id=auth.uid() or public.is_admin())));

drop policy if exists ratings_read_signed_in on public.technician_ratings;
create policy ratings_read_signed_in on public.technician_ratings for select to authenticated using(true);
drop policy if exists ratings_insert_completed_customer on public.technician_ratings;
create policy ratings_insert_completed_customer on public.technician_ratings for insert to authenticated
with check(customer_id=auth.uid() and exists(select 1 from public.service_requests r
 where r.id=request_id and r.customer_id=auth.uid() and r.technician_id=technician_id and r.status='completed'));

drop policy if exists plans_read_active on public.subscription_plans;
create policy plans_read_active on public.subscription_plans for select to authenticated
using(active or public.is_admin());
drop policy if exists plans_admin_manage on public.subscription_plans;
create policy plans_admin_manage on public.subscription_plans for all to authenticated
using(public.is_admin()) with check(public.is_admin());

drop policy if exists subscriptions_read_owner on public.subscriptions;
create policy subscriptions_read_owner on public.subscriptions for select to authenticated
using(user_id=auth.uid() or public.is_admin());

revoke all on function public.create_service_request(text,text,text,text,uuid,text,double precision,double precision) from public;
grant execute on function public.create_service_request(text,text,text,text,uuid,text,double precision,double precision) to authenticated;
revoke all on function public.reassign_service_request(uuid,uuid) from public;
grant execute on function public.reassign_service_request(uuid,uuid) to authenticated;
revoke all on function public.update_request_status(uuid,text,text) from public;
grant execute on function public.update_request_status(uuid,text,text) to authenticated;
revoke all on function public.request_subscription(text) from public;
grant execute on function public.request_subscription(text) to authenticated;
grant select on public.profiles, public.service_areas, public.technician_profiles,
 public.service_requests, public.request_events, public.technician_ratings,
 public.subscription_plans, public.subscriptions to authenticated;
grant insert on public.technician_profiles, public.technician_ratings to authenticated;
grant update on public.service_areas, public.subscription_plans to authenticated;
grant delete on public.service_areas, public.subscription_plans to authenticated;

grant select on public.technician_rating_summary to authenticated;

insert into public.subscription_plans(account_type,plan_code,title,price_toman,duration_days)
values
 ('customer','ten_day','اشتراک مشتری ۱۰ روزه',0,10),
 ('customer','monthly','اشتراک مشتری ماهانه',0,30),
 ('technician','ten_day','اشتراک فنی‌کار ۱۰ روزه',0,10),
 ('technician','monthly','اشتراک فنی‌کار ماهانه',0,30)
on conflict(account_type,plan_code) do nothing;

-- Add the verified Gorgan area list to service_areas before enabling request registration.
