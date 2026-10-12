// Atlasxis — fixtures de certificação da auditoria de RLS por tabela.
//
// Ground truth POR CONSTRUÇÃO, a partir da semântica documentada do
// PostgreSQL/Supabase (policies permissivas combinam com OR, restritivas com
// AND; sem policy permissiva com RLS ligado = nega; sem privilégio = nega;
// RLS desligado = privilégio decide). NUNCA derivado da saída do motor.
//
// expect: "tabela/papel/op" → reason code esperado (exato).
// mustNot: "tabela/papel/op" → status que NÃO pode aparecer (para armadilhas).
// kind: positive | negative | adversarial

const notes = (extra = "") => `create table public.notes (id uuid primary key, user_id uuid references auth.users(id), body text);${extra}`;
const C = "CONTROLLED", V = "VULNERABLE";

export const RLS_AUDIT_CASES = [
  // ---------------- POSITIVOS: CONTROLLED ----------------
  { id: "P01-owner-select", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy own on public.notes for select to authenticated using (auth.uid() = user_id);`),
    expect: { "notes/authenticated/select": "CONTROLLED_RLS_POLICY_OWNER", "notes/anon/select": "CONTROLLED_RLS_DEFAULT_DENY" } },
  { id: "P02-subselect-uid", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy own on public.notes for select using ((select auth.uid()) = user_id);`),
    expect: { "notes/authenticated/select": "CONTROLLED_RLS_POLICY_OWNER", "notes/anon/select": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "P03-pgdump-form", kind: "positive", opts: { schemaDump: true },
    sql: `-- PostgreSQL database dump
CREATE TABLE public.notes (id uuid NOT NULL, user_id uuid, body text);
ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON public.notes FOR SELECT TO authenticated USING ((( SELECT auth.uid() AS uid) = user_id));
GRANT ALL ON TABLE public.notes TO authenticated;`,
    expect: { "notes/authenticated/select": "CONTROLLED_RLS_POLICY_OWNER", "notes/anon/select": "CONTROLLED_PRIVILEGE_NOT_GRANTED" } },
  { id: "P04-owner-update-check", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy upd on public.notes for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);`),
    expect: { "notes/authenticated/update": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "P05-owner-insert", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy ins on public.notes for insert to authenticated with check (auth.uid() = user_id);`),
    expect: { "notes/authenticated/insert": "CONTROLLED_RLS_POLICY_OWNER", "notes/authenticated/select": "CONTROLLED_RLS_DEFAULT_DENY" } },
  { id: "P06-owner-delete-reversed", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy del on public.notes for delete to authenticated using (user_id = auth.uid());`),
    expect: { "notes/authenticated/delete": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "P07-restrictive-owner-and", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy open on public.notes for select using (true);
      create policy gate on public.notes as restrictive for select using (auth.uid() = user_id);`),
    expect: { "notes/authenticated/select": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "P08-revoke-anon", kind: "positive",
    sql: notes(`revoke all on public.notes from anon;`),
    expect: { "notes/anon/select": "CONTROLLED_PRIVILEGE_NOT_GRANTED", "notes/anon/delete": "CONTROLLED_PRIVILEGE_NOT_GRANTED", "notes/authenticated/select": "INSUFFICIENT_RLS_NOT_ENABLED_IN_CORPUS" } },
  { id: "P09-rls-no-policy", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;`),
    expect: { "notes/anon/select": "CONTROLLED_RLS_DEFAULT_DENY", "notes/authenticated/update": "CONTROLLED_RLS_DEFAULT_DENY" } },
  { id: "P10-if-exists-enable", kind: "positive",
    sql: notes(`alter table if exists public.notes enable row level security;
      create policy own on public.notes for select to authenticated using (auth.uid() = user_id);`),
    expect: { "notes/authenticated/select": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "P11-admin-function", kind: "positive",
    sql: `create table public.profiles (id uuid primary key references auth.users(id), role text);
      create or replace function public.is_admin() returns boolean language sql security definer as $$
        select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') $$;
      ${notes(`alter table public.notes enable row level security;
      create policy adm on public.notes for select to authenticated using (is_admin() or auth.uid() = user_id);`)}`,
    expect: { "notes/authenticated/select": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "P12-dump-anon-no-grant", kind: "positive", opts: { schemaDump: true },
    sql: `-- PostgreSQL database dump
CREATE TABLE public.notes (id uuid NOT NULL, user_id uuid, body text);
GRANT ALL ON TABLE public.notes TO authenticated;`,
    expect: { "notes/anon/select": "CONTROLLED_PRIVILEGE_NOT_GRANTED", "notes/authenticated/select": "VULNERABLE_RLS_TABLE_EXPOSED" } },

  // ---------------- POSITIVOS: VULNERABLE ----------------
  { id: "V01-disable-grant-anon", kind: "positive",
    sql: notes(`alter table public.notes disable row level security;
      grant all on public.notes to anon;`),
    expect: { "notes/anon/select": "VULNERABLE_RLS_TABLE_EXPOSED", "notes/anon/update": "VULNERABLE_RLS_TABLE_EXPOSED", "notes/authenticated/select": "INSUFFICIENT_RLS_GRANTS_UNKNOWN" } },
  { id: "V02-dump-no-enable", kind: "positive", opts: { schemaDump: true },
    sql: `-- PostgreSQL database dump
CREATE TABLE public.notes (id uuid NOT NULL, user_id uuid, body text);
GRANT SELECT ON TABLE public.notes TO anon;`,
    expect: { "notes/anon/select": "VULNERABLE_RLS_TABLE_EXPOSED", "notes/anon/update": "CONTROLLED_PRIVILEGE_NOT_GRANTED" } },
  { id: "V03-open-update", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy upd on public.notes for update to authenticated using (true);
      grant update on public.notes to authenticated;`),
    expect: { "notes/authenticated/update": "VULNERABLE_RLS_POLICY_OPEN_WRITE", "notes/anon/update": "CONTROLLED_RLS_DEFAULT_DENY" } },
  { id: "V04-open-delete-public", kind: "positive",
    sql: notes(`alter table public.notes enable row level security;
      create policy del on public.notes for delete using (true);
      grant delete on public.notes to anon;`),
    expect: { "notes/anon/delete": "VULNERABLE_RLS_POLICY_OPEN_WRITE" } },
  { id: "V05-assume-default-grants", kind: "positive", opts: { assumeDefaultGrants: true },
    sql: notes(`alter table public.notes disable row level security;`),
    expect: { "notes/anon/select": "VULNERABLE_RLS_TABLE_EXPOSED", "notes/authenticated/delete": "VULNERABLE_RLS_TABLE_EXPOSED" } },
  { id: "V06-default-privileges", kind: "positive",
    sql: `alter default privileges in schema public grant all on tables to anon;
      ${notes(`alter table public.notes disable row level security;`)}`,
    expect: { "notes/anon/select": "VULNERABLE_RLS_TABLE_EXPOSED" } },
  { id: "V07-grant-public", kind: "positive",
    sql: notes(`alter table public.notes disable row level security;
      grant select on public.notes to public;`),
    expect: { "notes/anon/select": "VULNERABLE_RLS_TABLE_EXPOSED", "notes/authenticated/select": "VULNERABLE_RLS_TABLE_EXPOSED" } },

  // ---------------- NEGATIVOS: abstenção correta ----------------
  { id: "N01-never-enabled", kind: "negative",
    sql: notes(`grant all on public.notes to anon;`),
    expect: { "notes/anon/select": "INSUFFICIENT_RLS_NOT_ENABLED_IN_CORPUS" } },
  { id: "N02-disabled-grants-unknown", kind: "negative",
    sql: notes(`alter table public.notes disable row level security;`),
    expect: { "notes/anon/select": "INSUFFICIENT_RLS_GRANTS_UNKNOWN" } },
  { id: "N03-disabled-no-owner", kind: "negative",
    sql: `create table public.countries (code text primary key, name text);
      alter table public.countries disable row level security;
      grant select on public.countries to anon;`,
    expect: { "countries/anon/select": "INSUFFICIENT_RLS_OFF_UNOWNED" } },
  { id: "N04-open-read", kind: "negative",
    sql: notes(`alter table public.notes enable row level security;
      create policy rd on public.notes for select using (true);
      grant select on public.notes to anon;`),
    expect: { "notes/anon/select": "INSUFFICIENT_RLS_POLICY_UNPROVEN" } },
  { id: "N05-open-insert", kind: "negative",
    sql: notes(`alter table public.notes enable row level security;
      create policy ins on public.notes for insert with check (true);
      grant insert on public.notes to anon;`),
    expect: { "notes/anon/insert": "INSUFFICIENT_RLS_POLICY_UNPROVEN" } },
  { id: "N06-open-write-restrictive-unproven", kind: "negative",
    sql: notes(`alter table public.notes enable row level security;
      create policy upd on public.notes for update using (true);
      create policy r on public.notes as restrictive for update using (is_locked = false);
      grant update on public.notes to authenticated;`),
    expect: { "notes/authenticated/update": "INSUFFICIENT_RLS_POLICY_UNPROVEN" } },
  { id: "N07-open-write-grant-unknown", kind: "negative",
    sql: notes(`alter table public.notes enable row level security;
      create policy upd on public.notes for update using (true);`),
    expect: { "notes/authenticated/update": "INSUFFICIENT_RLS_GRANTS_UNKNOWN" } },
  { id: "N08-open-write-no-owner", kind: "negative",
    sql: `create table public.tags (id uuid primary key, label text);
      alter table public.tags enable row level security;
      create policy upd on public.tags for update using (true);
      grant update on public.tags to authenticated;`,
    expect: { "tags/authenticated/update": "INSUFFICIENT_RLS_POLICY_UNPROVEN" } },
  { id: "N09-column-grant", kind: "negative",
    sql: notes(`alter table public.notes disable row level security;
      grant select (id) on public.notes to anon;`),
    expect: { "notes/anon/select": "INSUFFICIENT_RLS_GRANTS_UNKNOWN" } },
  { id: "N10-storage-schema", kind: "negative",
    sql: `create policy p on storage.objects for select using (true);`,
    expect: { "objects/*/*": "NOT_ANALYZED_NON_PUBLIC_SCHEMA" } },
  { id: "N11-dump-without-acl", kind: "negative", opts: { schemaDump: true },
    sql: `-- PostgreSQL database dump
CREATE TABLE public.notes (id uuid NOT NULL, user_id uuid, body text);`,
    expect: { "notes/anon/select": "INSUFFICIENT_RLS_GRANTS_UNKNOWN" } },

  // ---------------- ADVERSARIAIS: armadilhas de falso CONTROLLED ----------------
  { id: "A01-owner-or-open-policy", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy own on public.notes for select using (auth.uid() = user_id);
      create policy open on public.notes for select using (true);`),
    mustNot: { "notes/authenticated/select": C, "notes/anon/select": C } },
  { id: "A02-or-true-inside", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy p on public.notes for select using (auth.uid() = user_id or true);`),
    mustNot: { "notes/authenticated/select": C } },
  { id: "A03-any-logged-in", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy p on public.notes for select using (auth.uid() is not null);`),
    mustNot: { "notes/authenticated/select": C } },
  { id: "A04-update-check-true", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy p on public.notes for update using (auth.uid() = user_id) with check (true);`),
    mustNot: { "notes/authenticated/update": C } },
  { id: "A05-anon-open-side-policy", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy own on public.notes for select to authenticated using (auth.uid() = user_id);
      create policy anon_all on public.notes for select to anon using (true);`),
    mustNot: { "notes/anon/select": C }, expect: { "notes/authenticated/select": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "A06-conditional-enable", kind: "adversarial",
    sql: notes(`do $$ begin if current_setting('app.env', true) = 'prod' then
        alter table public.notes enable row level security; end if; end $$;
      create policy own on public.notes for select using (auth.uid() = user_id);`),
    mustNot: { "notes/authenticated/select": C }, expect: { "notes/authenticated/select": "INSUFFICIENT_RLS_STATE_UNCERTAIN" } },
  { id: "A07-enabled-then-disabled", kind: "adversarial",
    sql: { "001.sql": notes(`alter table public.notes enable row level security;
        create policy own on public.notes for select using (auth.uid() = user_id);`),
      "002.sql": `alter table public.notes disable row level security; grant select on public.notes to anon;` },
    mustNot: { "notes/anon/select": C }, expect: { "notes/anon/select": "VULNERABLE_RLS_TABLE_EXPOSED" } },
  { id: "A08-owner-dropped-replaced-open", kind: "adversarial",
    sql: { "001.sql": notes(`alter table public.notes enable row level security;
        create policy own on public.notes for select using (auth.uid() = user_id);`),
      "002.sql": `drop policy own on public.notes; create policy own2 on public.notes for select using (true);` },
    mustNot: { "notes/authenticated/select": C } },
  { id: "A09-conflicting-recreate", kind: "adversarial",
    sql: { "001.sql": notes(`alter table public.notes enable row level security;
        create policy own on public.notes for select using (auth.uid() = user_id);`),
      "002.sql": `create policy own on public.notes for select using (true);` },
    mustNot: { "notes/authenticated/select": C }, expect: { "notes/authenticated/select": "INSUFFICIENT_RLS_AMBIGUOUS" } },
  { id: "A10-conditional-grant", kind: "adversarial",
    sql: notes(`alter table public.notes disable row level security;
      do $$ begin if true then grant all on public.notes to anon; end if; end $$;`),
    mustNot: { "notes/anon/select": V }, expect: { "notes/anon/select": "INSUFFICIENT_RLS_STATE_UNCERTAIN" } },
  { id: "A11-helper-with-args", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy p on public.notes for select using (owns_note(id));`),
    mustNot: { "notes/authenticated/select": C } },
  { id: "A12-fake-admin-helper", kind: "adversarial",
    sql: `create or replace function public.is_admin() returns boolean language sql as $$ select true $$;
      ${notes(`alter table public.notes enable row level security;
      create policy p on public.notes for select using (is_admin());`)}`,
    mustNot: { "notes/authenticated/select": C } },
  { id: "A13-revoke-then-grant-public", kind: "adversarial",
    sql: notes(`alter table public.notes disable row level security;
      revoke all on public.notes from anon;
      grant select on public.notes to public;`),
    mustNot: { "notes/anon/select": C }, expect: { "notes/anon/select": "VULNERABLE_RLS_TABLE_EXPOSED" } },
  { id: "A14-grant-all-tables-before-create", kind: "adversarial",
    sql: `grant all on all tables in schema public to anon;
      ${notes(`alter table public.notes disable row level security;`)}`,
    mustNot: { "notes/anon/select": V }, expect: { "notes/anon/select": "INSUFFICIENT_RLS_GRANTS_UNKNOWN" } },
  { id: "A15-for-all-owner-plus-select-open", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy own on public.notes for all using (auth.uid() = user_id);
      create policy rd on public.notes for select using (true);`),
    mustNot: { "notes/authenticated/select": C }, expect: { "notes/authenticated/update": "CONTROLLED_RLS_POLICY_OWNER" } },
  { id: "A16-insert-check-missing-for-all", kind: "adversarial",
    sql: notes(`alter table public.notes enable row level security;
      create policy p on public.notes for all using (true) with check (auth.uid() = user_id);`),
    mustNot: { "notes/authenticated/select": C, "notes/authenticated/update": C } },
];

// Mutações causais: para cada célula CONTROLLED/VULNERABLE esperada, remover o
// elemento que sustenta a decisão TEM que mudar a decisão (senão a prova não é causal).
export const RLS_MUTATORS = {
  CONTROLLED_RLS_POLICY_OWNER: [
    { name: "dono→true", apply: (s) => s
        .replace(/\(\s*select\s+auth\.uid\(\)\s*(?:as\s+\w+)?\s*\)\s*=\s*\w+/gi, "true")
        .replace(/auth\.uid\(\)\s*=\s*\w+/gi, "true")
        .replace(/\w+\s*=\s*auth\.uid\(\)/gi, "true") },
  ],
  CONTROLLED_RLS_DEFAULT_DENY: [
    { name: "remove ENABLE", apply: (s) => s.replace(/alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?[\w."]+\s+enable\s+row\s+level\s+security;?/gi, "") },
  ],
  CONTROLLED_PRIVILEGE_NOT_GRANTED: [
    { name: "concede a todos", apply: (s) => s.replace(/revoke\s+all\s+on\s+[\w."]+\s+from\s+anon;?/gi, "") + "\ngrant all on public.notes to anon, authenticated;" },
  ],
  VULNERABLE_RLS_TABLE_EXPOSED: [
    { name: "liga RLS sem policy", apply: (s) => s.replace(/disable\s+row\s+level\s+security/gi, "enable row level security") + "\nalter table public.notes enable row level security;", opts: {} },
  ],
  VULNERABLE_RLS_POLICY_OPEN_WRITE: [
    { name: "true→dono", apply: (s) => s.replace(/using\s*\(\s*true\s*\)/gi, "using (auth.uid() = user_id)") },
  ],
};
