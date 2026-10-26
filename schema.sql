-- =====================================================================
-- MADALUX — banco de dados e regras de segurança (Supabase / PostgreSQL)
-- Execute este arquivo inteiro uma vez em: Supabase > SQL Editor > New query
-- =====================================================================

-- 1) Tabelas ------------------------------------------------------------
create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  email       text not null,
  name        text not null default '',
  role        text not null default 'user'    check (role   in ('user','admin')),
  status      text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at  timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id)
);

-- Dados financeiros de cada usuário (contas, lançamentos e metas em JSON)
create table public.user_data (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  data       jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

-- Registro de ações administrativas (auditoria)
create table public.admin_actions (
  id           bigint generated always as identity primary key,
  admin_id     uuid not null,
  target_id    uuid not null,
  target_email text,
  action       text not null check (action in ('approved','rejected')),
  created_at   timestamptz not null default now()
);

alter table public.profiles      enable row level security;
alter table public.user_data     enable row level security;
alter table public.admin_actions enable row level security;

-- 2) Funções auxiliares (executam no servidor, ignorando RLS de forma controlada)
create function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'admin' and status = 'approved');
$$;

create function public.is_approved() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and status = 'approved');
$$;

-- 3) Políticas de acesso (RLS) -----------------------------------------
-- profiles: cada um lê só o próprio perfil; o admin lê todos.
-- NÃO há política de INSERT/UPDATE/DELETE: ninguém altera status ou papel pelo cliente.
create policy profiles_select on public.profiles
  for select to authenticated using (id = auth.uid() or public.is_admin());

-- user_data: somente o dono E somente se estiver aprovado.
create policy user_data_select on public.user_data
  for select to authenticated using (user_id = auth.uid() and public.is_approved());
create policy user_data_insert on public.user_data
  for insert to authenticated with check (user_id = auth.uid() and public.is_approved());
create policy user_data_update on public.user_data
  for update to authenticated using (user_id = auth.uid() and public.is_approved())
  with check (user_id = auth.uid() and public.is_approved());
create policy user_data_delete on public.user_data
  for delete to authenticated using (user_id = auth.uid() and public.is_approved());

-- admin_actions: somente o admin lê; ninguém grava direto (só a função abaixo).
create policy admin_actions_select on public.admin_actions
  for select to authenticated using (public.is_admin());

revoke all on public.profiles, public.user_data, public.admin_actions from anon;
revoke insert, update, delete on public.profiles, public.admin_actions from authenticated;

-- 4) Todo cadastro novo nasce "pendente" e "user" (o papel nunca vem do cliente)
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, name, role, status)
  values (new.id, new.email, left(coalesce(new.raw_user_meta_data->>'name', ''), 120), 'user', 'pending');
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 5) Aprovar / recusar: única porta de entrada, valida o admin NO SERVIDOR
create function public.set_user_status(target uuid, new_status text) returns void
language plpgsql security definer set search_path = public as $$
declare v_email text;
begin
  if not public.is_admin() then
    raise exception 'Apenas o administrador pode alterar solicitações.' using errcode = '42501';
  end if;
  if new_status not in ('approved','rejected') then
    raise exception 'Status inválido.';
  end if;
  if target = auth.uid() then
    raise exception 'Você não pode alterar a própria conta.';
  end if;

  update public.profiles
     set status = new_status, reviewed_at = now(), reviewed_by = auth.uid()
   where id = target and role <> 'admin'
   returning email into v_email;

  if not found then
    raise exception 'Usuário não encontrado.';
  end if;

  insert into public.admin_actions (admin_id, target_id, target_email, action)
  values (auth.uid(), target, v_email, new_status);
end;
$$;

revoke execute on function public.set_user_status(uuid, text) from public, anon;
grant  execute on function public.set_user_status(uuid, text) to authenticated;

-- =====================================================================
-- 6) DEPOIS de rodar tudo acima:
--    a) Abra o site e crie sua conta normalmente (e confirme o e-mail, se pedido).
--    b) Volte ao SQL Editor e promova SUA conta a administradora (troque o e-mail):
--
--    update public.profiles
--       set role = 'admin', status = 'approved'
--     where email = 'SEU_EMAIL_AQUI';
--
--    Isso só é possível aqui no painel do Supabase (você é o dono do banco).
--    Nenhum visitante consegue se tornar admin pelo site.
-- =====================================================================
