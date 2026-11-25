-- 1. Extensão para UUID (geralmente já ativa no Supabase)
create extension if not exists "pgcrypto";

-- 2. Tabela de perfis de usuário
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null unique,
  full_name text not null default '',
  role text not null default 'user' check (role in ('user', 'admin')),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'blocked')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- 3. Tabela de dados financeiros por usuário
create table if not exists public.user_data (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- 4. Tabela de log de ações administrativas
create table if not exists public.admin_actions (
  id uuid primary key default gen_random_uuid(),
  admin_id uuid not null references public.profiles(id) on delete cascade,
  target_user_id uuid references public.profiles(id) on delete set null,
  action text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

-- Índices úteis
create index if not exists idx_profiles_status on public.profiles(status);
create index if not exists idx_profiles_role on public.profiles(role);
create index if not exists idx_admin_actions_created_at on public.admin_actions(created_at desc);

-- 5. Função auxiliar para atualizar updated_at automaticamente
create or replace function public.handle_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_profiles_updated_at on public.profiles;
create trigger trg_profiles_updated_at
before update on public.profiles
for each row
execute function public.handle_updated_at();

drop trigger if exists trg_user_data_updated_at on public.user_data;
create trigger trg_user_data_updated_at
before update on public.user_data
for each row
execute function public.handle_updated_at();

-- 6. Função auxiliar para verificar se o usuário autenticado é admin
create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles
    where id = auth.uid()
      and (
        role = 'admin'
        or lower(email) = 'lucasgabriel.leite3@gmail.com'
      )
  );
$$;

-- 7. Trigger ao criar usuário no auth.users -> cria linha em profiles e user_data
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_is_admin boolean;
  v_name text;
begin
  v_is_admin := lower(coalesce(new.email, '')) = 'lucasgabriel.leite3@gmail.com';
  v_name := coalesce(
    nullif(trim(new.raw_user_meta_data->>'full_name'), ''),
    split_part(coalesce(new.email, ''), '@', 1)
  );

  insert into public.profiles (id, email, full_name, role, status)
  values (
    new.id,
    lower(new.email),
    v_name,
    case when v_is_admin then 'admin' else 'user' end,
    case when v_is_admin then 'approved' else 'pending' end
  )
  on conflict (id) do update
  set
    email = excluded.email,
    full_name = case when public.profiles.full_name = '' then excluded.full_name else public.profiles.full_name end,
    role = case when v_is_admin then 'admin' else public.profiles.role end,
    status = case when v_is_admin then 'approved' else public.profiles.status end;

  insert into public.user_data (user_id, payload)
  values (
    new.id,
    '{"balance":0,"income":0,"expense":0,"transactions":[],"goals":[]}'::jsonb
  )
  on conflict (user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row
execute function public.handle_new_user();

-- 8. RPC segura para alterar status/papel de usuário (apenas admin)
create or replace function public.set_user_status(
  p_target_user_id uuid,
  p_new_status text,
  p_new_role text default null
)
returns public.profiles
language plpgsql
security definer
set search_path = public
as $$
declare
  v_updated public.profiles;
begin
  if auth.uid() is null then
    raise exception 'Usuário não autenticado.';
  end if;

  if not public.is_admin() then
    raise exception 'Acesso negado: apenas administradores podem alterar status de usuários.';
  end if;

  if p_new_status not in ('pending', 'approved', 'rejected', 'blocked') then
    raise exception 'Status inválido: %', p_new_status;
  end if;

  if p_new_role is not null and p_new_role not in ('user', 'admin') then
    raise exception 'Role inválido: %', p_new_role;
  end if;

  update public.profiles
  set
    status = p_new_status,
    role = coalesce(p_new_role, role),
    updated_at = now()
  where id = p_target_user_id
  returning * into v_updated;

  if not found then
    raise exception 'Perfil de usuário não encontrado.';
  end if;

  insert into public.admin_actions (admin_id, target_user_id, action, details)
  values (
    auth.uid(),
    p_target_user_id,
    'update_user_status',
    jsonb_build_object(
      'new_status', p_new_status,
      'new_role', v_updated.role,
      'target_email', v_updated.email
    )
  );

  return v_updated;
end;
$$;

-- Permissões de execução da RPC
revoke all on function public.set_user_status(uuid, text, text) from public;
grant execute on function public.set_user_status(uuid, text, text) to authenticated;

-- 9. Ativar Row Level Security (RLS)
alter table public.profiles enable row level security;
alter table public.user_data enable row level security;
alter table public.admin_actions enable row level security;

-- Políticas para profiles
drop policy if exists "profiles_select_own_or_admin" on public.profiles;
create policy "profiles_select_own_or_admin"
on public.profiles
for select
to authenticated
using (id = auth.uid() or public.is_admin());

drop policy if exists "profiles_insert_own" on public.profiles;
create policy "profiles_insert_own"
on public.profiles
for insert
to authenticated
with check (id = auth.uid());

drop policy if exists "profiles_update_own_safe" on public.profiles;
create policy "profiles_update_own_safe"
on public.profiles
for update
to authenticated
using (id = auth.uid() or public.is_admin())
with check (
  public.is_admin()
  or (
    id = auth.uid()
    and role = 'user'
  )
);

-- Políticas para user_data
drop policy if exists "user_data_all_own_or_admin" on public.user_data;
create policy "user_data_all_own_or_admin"
on public.user_data
for all
to authenticated
using (user_id = auth.uid() or public.is_admin())
with check (user_id = auth.uid() or public.is_admin());

-- Políticas para admin_actions
drop policy if exists "admin_actions_select_admin" on public.admin_actions;
create policy "admin_actions_select_admin"
on public.admin_actions
for select
to authenticated
using (public.is_admin());

drop policy if exists "admin_actions_insert_admin" on public.admin_actions;
create policy "admin_actions_insert_admin"
on public.admin_actions
for insert
to authenticated
with check (public.is_admin() and admin_id = auth.uid());
