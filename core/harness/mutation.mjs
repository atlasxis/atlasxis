// ORÁCULO CORE — mutation testing (FASE 6).
// Parte de casos CONTROLLED e aplica mutações que REMOVEM a causa da
// autorização. Cada mutação que remove a causa NÃO pode continuar CONTROLLED.
// Um survivor (mutante que ainda dá CONTROLLED) é reportado, nunca mascarado.
//
// Mutações são textuais mas ancoradas em regex específicas; cada uma declara
// o que espera. `applies` filtra: só contamos a mutação se ela realmente
// alterou o código (senão não é um survivor, é uma não-aplicação).

import { analyzeFileIR } from "../engine.mjs";

// catálogo de mutações. Cada uma: {id, desc, mutate(code)->code|null}
// null = não aplicável a este código.
const MUT = [
  { id: "M01-owner-other-user", desc: "troca user.id por otherId no gate de ownership",
    mutate: (c) => c.includes("!==user.id") || c.includes("!== user.id") ? c.replace(/!==\s*user\.id/, "!==otherId") : null },
  { id: "M02-sink-id", desc: "troca o id do sink (.eq('id',id)→otherId) e liga otherId como client source",
    mutate: (c) => { const m = c.match(/(\.(?:update|delete)\([^)]*\)(?:\.[a-z]+\([^)]*\))*?\.eq\("id",)\s*id\s*\)/); if (!m) return null;
      let out = c.replace(m[0], m[1] + "otherId)");
      // garante que otherId seja uma source do cliente (senão o sink cai fora de aplicabilidade)
      if (/const\s*\{\s*id\s*\}\s*=\s*await params/.test(out)) out = out.replace(/const\s*\{\s*id\s*\}(\s*=\s*await params)/, "const {id,otherId}$1");
      else if (!/otherId/.test(c)) return null;
      return out; } },
  { id: "M03-read-id", desc: "troca o id do read de ownership",
    mutate: (c) => { const m = c.match(/(select\("id,user_id"\)\.eq\("id",)id\)/); return m ? c.replace(m[0], m[1] + "otherId)") : null; } },
  { id: "M04-remove-guard", desc: "remove o if de rejeição de ownership",
    mutate: (c) => /if\([^)]*user\.id\)[^;]*(throw|return)[^;]*;?/.test(c) ? c.replace(/if\([^{]*user\.id[^{]*\)\s*(throw new Error\("403"\);|return[^;]*;)/, "") : null },
  { id: "M05-invert-guard-op", desc: "inverte !== para === no gate",
    mutate: (c) => /\.user_id\s*!==\s*user\.id/.test(c) ? c.replace(/\.user_id\s*!==\s*user\.id/, ".user_id===user.id") : null },
  { id: "M06-owner-column", desc: "troca a coluna owner (user_id→other_id) no gate",
    mutate: (c) => /\.user_id\s*!==\s*user\.id/.test(c) ? c.replace(/\.user_id(\s*!==\s*user\.id)/, ".other_id$1") : null },
  { id: "M07-and-to-or", desc: "troca && por || no gate composto (admin&&owner→admin||owner)",
    mutate: (c) => c.includes("&&") && /!==/.test(c) ? c.replace("&&", "||") : null },
  { id: "M08-gate-after-sink", desc: "move o gate para depois do sink (troca ordem)",
    mutate: (c) => {
      const gm = c.match(/if\([^{]*\.user_id[^{]*\)\s*throw new Error\("403"\);/);
      const sm = c.match(/await [\w.]+\.from\("[^"]+"\)\.(update|delete)\([^;]*;/);
      if (!gm || !sm) return null;
      let out = c.replace(gm[0], "__GATE__").replace(sm[0], sm[0] + " " + gm[0]);
      return out.replace("__GATE__", "");
    } },
  { id: "M09-dead-guard", desc: "embrulha o gate em if(false)",
    mutate: (c) => { const gm = c.match(/if\([^{]*\.user_id[^{]*\)\s*throw new Error\("403"\);/); return gm ? c.replace(gm[0], "if(false){ " + gm[0] + " }") : null; } },
  { id: "M10-remove-admin-branch", desc: "remove o disjunto admin do gate (mantém owner) — deve continuar CONTROLLED",
    expectControlled: true,
    mutate: (c) => /role==="admin"\|\|/.test(c) ? c.replace(/prof\?\.role==="admin"\|\|/, "") : (/isAdmin\|\|/.test(c) ? c.replace(/isAdmin\s*\|\|\s*/, "") : null) },
  { id: "M11-remove-owner-keep-admin", desc: "remove o disjunto owner (mantém só admin) → não prova ownership do recurso",
    mutate: (c) => /c\.user_id===user\.id\|\|/.test(c) ? c.replace(/c\.user_id===user\.id\s*\|\|\s*/, "") : (/post\.user_id===user\.id\|\|/.test(c) ? c.replace(/post\.user_id===user\.id\s*\|\|\s*/, "") : null) },
  { id: "M12-swap-verified-object", desc: "verifica objeto A mas o sink usa objeto B (troca o read)",
    mutate: (c) => { const m = c.match(/from\("(\w+)"\)\.select\("id,user_id"\)\.eq\("id",id\)/); return m && m[1] ? c.replace(m[0], `from("outra_tabela").select("id,user_id").eq("id",id)`) : null; } },
  { id: "M13-break-transitive-user", desc: "troca user.id por outro no membership transitivo",
    mutate: (c) => c.includes('.eq("user_id",user.id)') ? c.replace('.eq("user_id",user.id)', '.eq("user_id",otherUserId)') : null },
  { id: "M14-break-transitive-fk", desc: "troca o fk derivado por id do cliente no membership",
    mutate: (c) => c.includes('.eq("team_id",lineup.team_id)') ? c.replace('.eq("team_id",lineup.team_id)', '.eq("team_id",teamId)') : null },
];

export async function runMutations(namedFixtures, opts = {}) {
  const results = [];
  for (const fx of namedFixtures) {
    const base = analyzeFileIR(fx.files, fx.entry, fx.rls || {});
    const baseStatus = base[0].decision.status;
    if (baseStatus !== "CONTROLLED") continue; // só mutamos CONTROLLED
    const entryCode = fx.files[fx.entry];
    for (const m of MUT) {
      const mutatedCode = m.mutate(entryCode);
      if (mutatedCode == null || mutatedCode === entryCode) continue; // não aplicável
      const mfiles = { ...fx.files, [fx.entry]: mutatedCode };
      let res, status, reason;
      try { res = analyzeFileIR(mfiles, fx.entry, fx.rls || {}); status = res[0].decision.status; reason = res[0].decision.reasonCode; }
      catch (e) { status = "ERROR"; reason = e.message.slice(0, 80); }
      const expectControlled = !!m.expectControlled;
      const detected = expectControlled ? status === "CONTROLLED" : status !== "CONTROLLED";
      results.push({ fixture: fx.n, mutation: m.id, desc: m.desc, expectControlled, resultStatus: status, resultReason: reason, detected });
    }
  }
  return results;
}
