# Atlasxis — Authorization Proof Engine

[Português](README.pt-BR.md)

Atlasxis statically analyzes API routes (Next.js + Supabase) and answers one
question **per data sink**, with three possible outcomes:

> **"Is there enough structural evidence to prove authorization on this path?"**

- **`CONTROLLED`** — enough evidence of authorization (complete proof chain);
- **`VULNERABLE`** — positive evidence of a reachable path with no authorization;
- **`INSUFFICIENT_EVIDENCE` / `NOT_ANALYZED` / `OUT_OF_SCOPE_*`** — it could not prove either.

## Why it exists

Broken object-level authorization (IDOR/BOLA) is the top API security risk,
and it is the hardest to catch with pattern-based scanners: the bug is a
*missing* check, not a malicious construct. Checking that a Supabase table
*has* Row Level Security is not the same as checking that the policy actually
restricts rows to their owner. Atlasxis tries to **prove** the authorization
chain, and refuses to guess when it can't.

## What it is NOT

- **Not** a generic vulnerability scanner (XSS, SQLi, secrets, dependencies).
- It **never** says "your app is secure". No findings is not proof of security.
- It **never** turns missing evidence into a verdict: when it can't prove, it
  **abstains** and tells you why.
- It **never** runs the code it analyzes. The analysis is 100% static.

This contract (CORRECTNESS > COVERAGE) is formalized in
[PRODUCT-CONTRACT.md](PRODUCT-CONTRACT.md).

## Install

Requires Node ≥ 20.

```bash
npm install --save-dev atlasxis
```

Or run it once without installing:

```bash
npx atlasxis scan .
```

## Usage

```bash
npx atlasxis scan .                        # markdown report
npx atlasxis scan . --format json          # machine-readable
npx atlasxis scan . --format sarif         # for code-scanning tools
npx atlasxis scan . --ci                   # CI policy (exit 2 if VULNERABLE)
npx atlasxis report . --out proof.md       # per-sink proof report (file + line)
npx atlasxis explain INSUFFICIENT_RLS_UNKNOWN
npx atlasxis version
```

With RLS evidence from your migrations:

```bash
npx atlasxis scan . --rls ./supabase/migrations
```

## Example output

Run it against one of the synthetic fixtures in this repository:

```bash
git clone https://github.com/fisioterapeutah-star/atlasxis.git && cd atlasxis
npm install
npx atlasxis report public-corpus/service-role-vuln
```

```
### VULNERABLE — `DELETE public-corpus/service-role-vuln/src/app/api/notes/[id]/route.ts`
- Sink: delete `notes` (client: service_role)
- Reason code: VULNERABLE_NO_GATING_SERVICE_ROLE
- ProofChain:
    SOURCE        id                      (client-controlled)
    RESOURCE      notes id=id
    GUARD         (no live guard found)
    IDENTITY      same=false
    SINK          delete notes            (service_role — bypasses RLS)
```

Every decision carries a **stable reason code** and, when there is proof, a
**ProofChain**: source → resource → authorization → guard → identity → sink,
with structural witnesses and explicit assumptions. `VULNERABLE` requires
**positive** evidence (controllable input + reachable sink + proven absence of
any gating). It is never emitted just because "no ownership check was found".

> The report text is currently in Portuguese. Reason codes, JSON and SARIF
> output are language-neutral.

## Reading the verdicts

| Verdict | Means | Does NOT mean |
|---|---|---|
| `CONTROLLED` | Intact ProofChain: structural evidence of authorization for this path | that the rest of the system is secure |
| `VULNERABLE` | **positive** evidence of reachable unauthorized access | (only emitted with positive proof, never from absence) |
| `INSUFFICIENT_EVIDENCE` | could not prove authorization nor vulnerability | **NOT `SAFE`** — needs human review |
| `NOT_ANALYZED` | outside what the engine models (syntax/framework/sink) | **NOT `SAFE`** — needs human review |
| `OUT_OF_SCOPE_PROVEN` | route proven admin-only or webhook: the ownership model does not apply | that the admin operation is desirable (policy, not proof) |

`atlasxis explain <REASON_CODE>` details any of the 35 reason codes: what it
proves and what it does **not** prove. **Absence of proof is not proof of absence.**

## CI

The simplest setup is the npm package:

```yaml
# .github/workflows/atlasxis.yml
name: atlasxis
on: [pull_request]
jobs:
  authz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npx --yes atlasxis scan . --ci
```

Explicit policy: **only `VULNERABLE` fails the build** (use `--fail-on
insufficient` to make it stricter). `INSUFFICIENT` and `NOT_ANALYZED` are
**never** treated as safe; they are always reported.

A composite action is also available in
[.github/actions/atlasxis-scan](.github/actions/atlasxis-scan).

## Limitations (read before trusting it)

Current scope: Next.js App/Pages Router **API routes** + Supabase JS client,
with RLS read from SQL migrations. Server actions, client-side Supabase calls,
Prisma/Drizzle and other frameworks are outside the model and come out as
`NOT_ANALYZED` or are not discovered at all — never as a verdict. The full,
honest list is in [docs/LIMITATIONS.md](docs/LIMITATIONS.md) (Portuguese).
**Independent human validation: PENDING.**

## Validation (public corpus)

Every number below is reproducible with `npm test` in this repository and comes
**only from the public corpus**. Details in [docs/PUBLIC-METRICS.md](docs/PUBLIC-METRICS.md).

- **532 synthetic cases** labeled by construction: 0 false-control, 0 false-vuln;
- **Mutation testing** on CONTROLLED fixtures: 0 survivors;
- **17 adversarial patterns** designed to trick it into a false `CONTROLLED`: correct abstention on all;
- **8 synthetic mini-projects** ([`public-corpus/`](public-corpus/)) demonstrating each mechanism, Proof Integrity = 0;
- **Blind corpus** of 42 cases waiting for a human auditor ([blind-validation/](blind-validation/)).

> **Methodological honesty**: these recall numbers hold *on the synthetic
> corpus in this repository*. They measure whether the engine proves what the
> corpus contains, not what exists in the real world. **There is no real-world
> recall metric in this public distribution.**

## Trust model

- Atlasxis **proves** structural properties. It does not run code or observe
  runtime. A `CONTROLLED` proof is only as good as its *assumptions*, which are
  listed in every finding and in `atlasxis explain`.
- **False-control = 0** is the core of the product: it would rather abstain
  than risk a wrong `CONTROLLED`. Coverage is deliberately conservative.
- **`VULNERABLE` requires positive evidence**; it is never inferred from absence.
- New capabilities only enter the engine through a 10-requirement
  certification process, never through ad-hoc heuristics or automatic "learning".

## Operational security

Analyzing third-party code is treated as hostile: symlinks are not followed,
the target's lifecycle scripts never run, the target's `.env` is never read,
file/byte/time limits are enforced, and output is sanitized against secret
leaks. See [SECURITY.md](SECURITY.md) and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Architecture

Security IR → structural extraction (TypeScript AST) → per-mechanism proofs
(ownership helper/inline, post-read gate, transitive, RLS, role gate, webhook)
→ per-sink decision `(status, reasonCode)` → reports (markdown/JSON/SARIF).
See [ARCHITECTURE.md](ARCHITECTURE.md).

## Contributing

Report cases with **minimal synthetic code** (never private or third-party
code) using the issue templates. New capabilities follow the certification
process in [case-library/README.md](case-library/README.md). See
[CONTRIBUTING.md](CONTRIBUTING.md). Run `npm test` before opening a PR.

## License

[MIT](LICENSE). It covers the engine, the CLI, the documentation and the
synthetic fixtures in `public-corpus/`. No third-party code is redistributed.

Changes, and what was removed or replaced for privacy in the public
distribution: [CHANGELOG.md](CHANGELOG.md). Atlasxis was previously published
as ORÁCULO CORE.
