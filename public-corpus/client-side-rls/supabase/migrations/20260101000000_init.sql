-- Fixture pública sintética para `atlasxis rls`. Cada tabela exercita um mecanismo.

-- profiles: RLS ligado + policies de dono → CONTROLLED
create table public.profiles (
  id uuid primary key references auth.users(id),
  display_name text
);
alter table public.profiles enable row level security;
create policy profiles_select_own on public.profiles for select to authenticated using (auth.uid() = id);
create policy profiles_update_own on public.profiles for update to authenticated
  using (auth.uid() = id) with check (auth.uid() = id);

-- messages: RLS desligado de forma explícita + GRANT para anon → VULNERABLE
-- (padrão do caso público CVE-2025-48757: tabela lida/escrita com a chave anon)
create table public.messages (
  id uuid primary key,
  sender_id uuid references auth.users(id),
  body text
);
alter table public.messages disable row level security;

-- todos: RLS ligado, mas UPDATE liberado para qualquer linha → VULNERABLE em UPDATE
create table public.todos (
  id uuid primary key,
  user_id uuid references auth.users(id),
  title text,
  done boolean default false
);
alter table public.todos enable row level security;
create policy todos_select_own on public.todos for select to authenticated using (auth.uid() = user_id);
create policy todos_update_any on public.todos for update to authenticated using (true);

-- countries: tabela pública de consulta, sem dono → abstenção (não é VULNERABLE)
create table public.countries (code text primary key, name text);
alter table public.countries disable row level security;

-- privilégios explícitos (padrão exigido pelo Supabase desde 2026)
grant select, insert, update, delete on public.messages to anon, authenticated;
grant select, insert, update, delete on public.todos to authenticated;
grant select on public.countries to anon, authenticated;
grant select, update on public.profiles to authenticated;
revoke all on public.profiles from anon;
