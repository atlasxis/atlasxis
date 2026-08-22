-- Política RLS sintética owner-scoped para a fixture pública rls-owner.
create table public.notes (id uuid primary key, user_id uuid not null);
alter table public.notes enable row level security;
create policy notes_select_own on public.notes for select using (auth.uid() = user_id);
