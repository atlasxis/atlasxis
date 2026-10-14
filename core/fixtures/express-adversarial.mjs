// Atlasxis — ataques ao motor Express + Prisma (revisão adversarial independente, 13/out/2026).
// Cada caso reproduz um defeito achado na primeira versão: 7 falsos CONTROLLED/OOS, 4 falsos
// VULNERABLE e 1 queda. Chave de acesso: "<VERBO> <caminho> <modelo>.<op>".

const SCHEMA = `
model User { id String @id  notes Note[] }
model Note {
  id String @id
  userId String
  user User @relation(fields: [userId], references: [id])
  folderId String?
  body String
}
model Folder {
  id String @id
  userId String
  user User @relation(fields: [userId], references: [id])
}
`;
const PRISMA = `import { PrismaClient } from "@prisma/client";\nconst prisma = new PrismaClient();\nexport default prisma;\n`;
const AUTH = `import jwt from "jsonwebtoken";
export function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({});
  try { const p = jwt.verify(h.slice(7), "s"); req.user = { id: p.sub }; return next(); }
  catch { return res.status(401).json({}); }
}
`;
const MW = `import jwt from "jsonwebtoken";
import prisma from "./prisma";
import { auth } from "./auth";
export function maybeAuth(req, res, next) {
  if (!req.headers.authorization) return next();
  return auth(req, res, next);
}
export function softAuth(req, res, next) {
  const h = req.headers.authorization;
  if (h) { try { req.user = jwt.verify(h.slice(7), "s"); } catch (e) { return res.status(401).json({}); } }
  next();
}
export function decodeAuth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({});
  req.user = verifyToken(h.slice(7));
  next();
}
function verifyToken(t) { return jwt.decode(t); }
export function requireRole(...roles) {
  return (req, res, next) => { if (!roles.includes(req.user.role)) return res.status(403).json({}); next(); };
}
export async function checkNoteOwner(req, res, next) {
  const n = await prisma.note.findUnique({ where: { id: req.params.id } });
  if (!n || n.userId !== req.user.id) return res.status(404).json({});
  next();
}
`;
const app = (body, imports = "") => ({ "src/prisma.ts": PRISMA, "src/auth.ts": AUTH, "src/mw.ts": MW, "src/app.ts": `import express from "express";\nimport prisma from "./prisma";\nimport { auth } from "./auth";\nimport { maybeAuth, softAuth, decodeAuth, requireRole, checkNoteOwner } from "./mw";\n${imports}\nconst app = express();\n${body}\nexport default app;\n` });
const H = (verb, body, mws = "auth", path = "/n/:id") => `app.${verb}("${path}", ${mws}, async (req, res, next) => { ${body} });`;
const S = { "prisma/schema.prisma": SCHEMA };
const NOT_CONTROLLED = (key) => ({ [key]: "CONTROLLED" });
const NOT_VULN = (key) => ({ [key]: "VULNERABLE" });

export const EXPRESS_ADVERSARIAL_CASES = [
  // ---- falsos CONTROLLED / OOS ----
  { id: "A01-role-member-is-not-admin", schemas: S, files: app(H("get", `res.json(await prisma.note.findUnique({ where: { id: req.params.id } }));`, "auth, requireRole('member')")), mustNotStatus: { "GET /n/:id note.findUnique": ["OUT_OF_SCOPE_PROVEN", "CONTROLLED"] } },
  { id: "A02-maybe-auth-optional", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user?.id } }));`, "maybeAuth")), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
  { id: "A03-soft-auth-optional", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user?.id } }));`, "softAuth")), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
  { id: "A04-soft-auth-public-catalog", schemas: S, files: app(H("get", `res.json(await prisma.note.findUnique({ where: { id: req.params.id } }));`, "softAuth")), mustNot: NOT_VULN("GET /n/:id note.findUnique") },
  { id: "A05-decode-is-not-verify", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`, "decodeAuth")), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
  { id: "A06-gate-without-return", schemas: S, files: app(H("get", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) { res.status(403).json({}); } res.json(n);`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findUnique") },
  { id: "A07-gate-next-without-return", schemas: S, files: app(H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) next(new Error("forbidden")); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
  { id: "A08-gate-swallowed-by-catch", schemas: S, files: app(H("delete", `try { const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) throw new Error("x"); } catch (e) { console.log(e); } await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
  { id: "A09-check-a-access-b", schemas: S, files: app(H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) return res.status(403).json({}); await prisma.note.delete({ where: { id: req.body.id } }); res.json(n);`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
  { id: "A10-id-reassigned-after-gate", schemas: S, files: app(H("delete", `let id = req.params.id; const n = await prisma.note.findUnique({ where: { id } }); if (n.userId !== req.user.id) return res.status(403).json({}); id = req.body.id; await prisma.note.delete({ where: { id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
  { id: "A11-is-owner-reassigned", schemas: S, files: app(H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); let isOwner = n.userId === req.user.id; if (req.query.force) isOwner = true; if (!isOwner) return res.status(403).json({}); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
  { id: "A12-identity-overwritten-conditionally", schemas: S, files: app(H("get", `if (req.body.asUser) req.user = { id: req.body.asUser }; res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
  { id: "A13-identity-id-overwritten", schemas: S, files: app(H("get", `req.user.id = req.query.uid; res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
  { id: "A14-update-moves-to-client-folder", schemas: S, files: app(H("put", `res.json(await prisma.note.updateMany({ where: { id: req.params.id, userId: req.user.id }, data: { folderId: req.body.folderId } }));`)), expect: { "PUT /n/:id note.updateMany": "INSUFFICIENT_CROSS_RESOURCE" } },
  { id: "A15-create-connects-client-folder", schemas: S, files: app(`app.post("/n", auth, async (req, res) => { res.json(await prisma.note.create({ data: { userId: req.user.id, folder: { connect: { id: req.body.folderId } } } })); });`), expect: { "POST /n note.create": "INSUFFICIENT_CROSS_RESOURCE" } },
  { id: "A16-shadowed-helper", schemas: S, files: app(`function assertOwner(n, uid) { if (n.userId !== uid) throw new Error("x"); }\napp.delete("/n/:id", auth, async (req, res) => { const assertOwner = (n, u) => {}; const n = await prisma.note.findUnique({ where: { id: req.params.id } }); assertOwner(n, req.user.id); await prisma.note.delete({ where: { id: req.params.id } }); res.json({}); });`), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
  { id: "A17-owner-in-or", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { OR: [{ id: req.params.id }, { userId: req.user.id }] } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
  { id: "A18-owner-in-not", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, NOT: { userId: req.user.id } } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
  { id: "A19-owner-not-operator", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: { not: req.user.id } } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },

  // ---- falsos VULNERABLE ----
  { id: "A20-gate-404", schemas: S, files: app(H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (!n || n.userId !== req.user.id) return res.status(404).json({}); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), expect: { "DELETE /n/:id note.delete": "CONTROLLED_POST_READ_GATE" } },
  { id: "A21-gate-block-status-return", schemas: S, files: app(H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) { res.status(403).json({}); return; } await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), expect: { "DELETE /n/:id note.delete": "CONTROLLED_POST_READ_GATE" } },
  { id: "A22-gate-return-next-create-error", schemas: S, files: app(H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) return next(createError(403)); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), expect: { "DELETE /n/:id note.delete": "CONTROLLED_POST_READ_GATE" } },
  { id: "A23-owner-in-spread-scope", schemas: S, files: app(H("get", `const scope = { userId: req.user.id }; res.json(await prisma.note.findFirst({ where: { id: req.params.id, ...scope } }));`)), mustNot: NOT_VULN("GET /n/:id note.findFirst") },
  { id: "A24-owner-in-and", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, AND: [{ userId: req.user.id }] } }));`)), mustNot: NOT_VULN("GET /n/:id note.findFirst") },
  { id: "A25-owner-from-res-locals", schemas: S, files: app(H("get", `const uid = res.locals.uid; res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: uid } }));`)), mustNot: NOT_VULN("GET /n/:id note.findFirst") },
  { id: "A26-identity-as-sub", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.sub } }));`)), mustNot: NOT_VULN("GET /n/:id note.findFirst") },
  { id: "A27-identity-as-userId", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.userId } }));`)), mustNot: NOT_VULN("GET /n/:id note.findFirst") },
  { id: "A28-gate-in-loop-without-block", schemas: S, files: app(H("delete", `const ns = await prisma.note.findMany({ where: { id: { in: req.body.ids } } }); for (const n of ns) if (n.userId !== req.user.id) return res.status(403).json({}); await prisma.note.deleteMany({ where: { id: { in: req.body.ids } } }); res.json({});`)), mustNot: NOT_VULN("DELETE /n/:id note.deleteMany") },
  { id: "A29-external-authorize", schemas: S, files: app(H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); authorize(req.user, n); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`), `import { authorize } from "@acme/authz";`), mustNot: NOT_VULN("DELETE /n/:id note.delete") },
  { id: "A30-external-validate-ownership", schemas: S, files: app(H("delete", `await validateOwnership(req.params.id, req.user.id); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`), `import { validateOwnership } from "@acme/authz";`), mustNot: NOT_VULN("DELETE /n/:id note.delete") },
  { id: "A31-ownership-middleware", schemas: S, files: app(H("delete", `await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`, "auth, checkNoteOwner")), mustNot: NOT_VULN("DELETE /n/:id note.delete") },
  { id: "A32-ownership-wrapper", schemas: S, files: app(`function withOwnedNote(fn) { return async (req, res) => { const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (!n || n.userId !== req.user.id) return res.status(403).json({}); return fn(req, res); }; }\napp.delete("/n/:id", auth, withOwnedNote(async (req, res) => { await prisma.note.delete({ where: { id: req.params.id } }); res.json({}); }));`), mustNot: NOT_VULN("DELETE /n/:id note.delete") },
  { id: "A33-router-param-preloader", schemas: S, files: app(`const r = express.Router();\nr.use(auth);\nr.param("id", async (req, res, next, id) => { const n = await prisma.note.findUnique({ where: { id } }); if (!n || n.userId !== req.user.id) return res.status(403).json({}); next(); });\nr.delete("/n/:id", async (req, res) => { await prisma.note.delete({ where: { id: req.params.id } }); res.json({}); });\napp.use(r);`), mustNot: NOT_VULN("DELETE /n/:id note.delete") },
  { id: "A34-use-prefix-is-segment", schemas: S, files: app(`const r = express.Router();\nr.use("/me", auth);\nr.get("/members/:id", async (req, res) => { res.json(await prisma.note.findUnique({ where: { id: req.params.id } })); });\napp.use("/api", r);`), mustNot: NOT_VULN("GET /api/members/:id note.findUnique") },
  { id: "A35-parent-scoped-admin-role", schemas: S, files: app(`const r = express.Router();\nr.get("/admin/notes/:id", async (req, res) => { res.json(await prisma.note.findUnique({ where: { id: req.params.id } })); });\napp.use(auth);\napp.use("/api/admin", requireRole("admin"));\napp.use("/api", r);`), mustNot: NOT_VULN("GET /api/admin/notes/:id note.findUnique") },
  { id: "A36-unresolved-check-in-object-arg", schemas: S, files: app(H("delete", `await audit.record({ ok: await canEdit(req.params.id, req.user.id) }); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`), `import { canEdit } from "./perm.js";\nimport { audit } from "./audit.js";`), mustNot: NOT_VULN("DELETE /n/:id note.delete") },

  // ---- segunda rodada (ataques às correções) ----
  ...(() => {
    const GATE = `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) throw new Error("forbidden");`;
    const ACL = SCHEMA + `\nmodel Share {\n  id String @id\n  noteId String\n  note Note @relation(fields: [noteId], references: [id])\n  userId String\n  user User @relation(fields: [userId], references: [id])\n}`;
    const MW2 = `import jwt from "jsonwebtoken";\nimport { assertNoteOwner } from "./guards";\nimport { verifyToken } from "./token.js";\nexport function catchAuth(req, res, next) {\n  try { req.user = jwt.verify(String(req.headers.authorization).slice(7), "s"); } catch { return next(); }\n  if (req.user.banned) return res.status(403).json({});\n  next();\n}\nexport function jsAuth(req, res, next) {\n  const h = req.headers.authorization;\n  if (!h) return res.status(401).json({});\n  req.user = verifyToken(h.slice(7));\n  next();\n}\nexport async function ownsNote(req, res, next) { await assertNoteOwner(req); next(); }\nexport function requireRole2(...roles) { return (req, res, next) => { if (!roles.includes(req.user.role)) return res.status(403).json({}); next(); }; }\n`;
    const extra = { "src/mw2.ts": MW2, "src/guards.ts": `import prisma from "./prisma";\nexport async function assertNoteOwner(req: any) { const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (!n || n.userId !== req.user.id) throw new Error("forbidden"); }\n`, "src/token.ts": `import jwt from "jsonwebtoken";\nexport function verifyToken(t: string) { return jwt.decode(t); }\n` };
    const imp2 = `import { catchAuth, jsAuth, ownsNote, requireRole2 } from "./mw2";`;
    const M = (code) => ({ ...app(code, imp2), ...extra });
    return [
      { id: "B01-catch-returns-only-sometimes", schemas: S, files: app(H("delete", `try { ${GATE} } catch (e) { if (e.code === "P2025") return res.status(404).json({}); console.error(e); } await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
      { id: "B02-helper-gate-promise-catch", schemas: S, files: app(`async function assertOwner(n, uid) { if (n.userId !== uid) throw new Error("x"); }\n` + H("delete", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); await assertOwner(n, req.user.id).catch(() => {}); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
      { id: "B03-destructuring-reassignment", schemas: S, files: app(H("delete", `let id = req.params.id; const n = await prisma.note.findUnique({ where: { id } }); if (n.userId !== req.user.id) return res.status(403).json({}); ({ id } = req.body); await prisma.note.delete({ where: { id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete"), handlerMustNot: { "DELETE /n/:id": ["CONTROLLED"] } },
      { id: "B04-object-assign-identity", schemas: S, files: app(H("get", `Object.assign(req.user, { id: req.query.as }); res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
      { id: "B05-identity-overwritten-in-helper", schemas: S, files: app(`function impersonate(r) { if (r.query.as) r.user = { id: r.query.as }; }\n` + H("get", `impersonate(req); res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
      { id: "B06-identity-key-not-set", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.userId } }));`)), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
      { id: "B07-id-reassigned-handler", schemas: S, files: app(H("delete", `let id = req.params.id; const n = await prisma.note.findUnique({ where: { id } }); if (n.userId !== req.user.id) return res.status(403).json({}); id = req.body.id; await prisma.note.delete({ where: { id } }); res.json({});`)), handlerMustNot: { "DELETE /n/:id": ["CONTROLLED"] } },
      { id: "B08-member-shadow", schemas: S, files: { ...app(H("delete", `const svc = { assertOwner: (a, b) => {} }; const n = await prisma.note.findUnique({ where: { id: req.params.id } }); svc.assertOwner(n, req.user.id); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`), `import { svc } from "./svc";`), "src/svc.ts": `export const svc = { assertOwner(n: any, uid: string) { if (n.userId !== uid) throw new Error("x"); } };\n` }, mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
      { id: "B09-destructured-shadow", schemas: S, files: app(`function assertOwner(n, uid) { if (n.userId !== uid) throw new Error("x"); }\nconst noop = { assertOwner: () => {} };\n` + H("delete", `const { assertOwner } = noop; const n = await prisma.note.findUnique({ where: { id: req.params.id } }); assertOwner(n, req.user.id); await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
      { id: "B10-acl-membership", schemas: { "prisma/schema.prisma": ACL }, files: app(H("put", `const share = await prisma.share.findFirst({ where: { noteId: req.params.id, userId: req.user.id } }); if (!share) return res.status(403).json({}); await prisma.note.update({ where: { id: req.params.id }, data: { body: req.body.body } }); res.json({});`)), mustNot: NOT_VULN("PUT /n/:id note.update") },
      { id: "B11-optional-auth-via-catch", schemas: S, files: M(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user?.id } }));`, "catchAuth")), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
      { id: "B12-decode-via-js-extension", schemas: S, files: M(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`, "jsAuth")), mustNot: NOT_CONTROLLED("GET /n/:id note.findFirst") },
      { id: "B13-checker-via-helper", schemas: S, files: M(H("delete", `await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`, "auth, ownsNote")), mustNot: NOT_VULN("DELETE /n/:id note.delete") },
      { id: "B14-role-user-or-admin", schemas: S, files: M(H("get", `res.json(await prisma.note.findUnique({ where: { id: req.params.id } }));`, "auth, requireRole2('user', 'admin')")), mustNotStatus: { "GET /n/:id note.findUnique": ["OUT_OF_SCOPE_PROVEN", "CONTROLLED"] } },
      { id: "B15-scoped-param-name", schemas: S, files: M(`app.use(auth);\napp.use("/n/:noteId", ownsNote);\napp.delete("/n/:id", async (req, res) => { await prisma.note.delete({ where: { id: req.params.id } }); res.json({}); });`), mustNot: NOT_VULN("DELETE /n/:id note.delete") },
      { id: "B16-mount-param-name-admin", schemas: S, files: M(`const r = express.Router();\nr.get("/admin/notes/:id", async (req, res) => { res.json(await prisma.note.findUnique({ where: { id: req.params.id } })); });\napp.use(auth);\napp.use("/orgs/:orgId/admin", requireRole2("admin"));\napp.use("/orgs/:id", r);`), mustNot: NOT_VULN("GET /orgs/:id/admin/notes/:id note.findUnique") },
      { id: "B17-read-then-external-authorize", schemas: S, files: app(H("get", `const n = await prisma.note.findUnique({ where: { id: req.params.id } }); authorize(req.user, n); res.json(n);`), `import { authorize } from "@acme/authz";`), mustNot: NOT_VULN("GET /n/:id note.findUnique") },
      { id: "B18-unrelated-identity-write-keeps-identity", schemas: S, files: app(H("get", `req.user.lastSeen = Date.now(); res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`)), expect: { "GET /n/:id note.findFirst": "CONTROLLED_SELF_SCOPE" } },
    ];
  })(),

  // ---- terceira rodada: proveniência da identidade, apelidos, catch com next(e), :param vs literal ----
  ...(() => {
    const OWN = `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.id } }));`;
    const MW3 = `import jwt from "jsonwebtoken";\nimport prisma from "./prisma";\nexport async function dbAuth(req, res, next) {\n  const h = req.headers.authorization; if (!h) return res.status(401).json({});\n  const p = jwt.verify(h.slice(7), "s");\n  req.user = await prisma.user.findUnique({ where: { id: p.sub } });\n  next();\n}\nexport function hdrAuth(req, res, next) {\n  const h = req.headers.authorization; if (!h) return res.status(401).json({});\n  jwt.verify(h.slice(7), "s");\n  req.user = { id: req.headers["x-user-id"] };\n  next();\n}\nexport function requireRole3(...roles) { return (req, res, next) => { if (!roles.includes(req.user.role)) return res.status(403).json({}); next(); }; }\n`;
    const M = (code) => ({ ...app(code, `import { dbAuth, hdrAuth, requireRole3 } from "./mw3";`), "src/mw3.ts": MW3 });
    const K = "GET /n/:id note.findFirst";
    return [
      { id: "C01-db-row-identity-other-key", schemas: S, files: M(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user.userId } }));`, "dbAuth")), mustNot: NOT_CONTROLLED(K) },
      { id: "C02-identity-from-header-after-verify", schemas: S, files: M(H("get", OWN, "hdrAuth")), mustNot: NOT_CONTROLLED(K) },
      { id: "C03-short-circuit-identity-write", schemas: S, files: app(H("get", `req.query.as && (req.user = { id: req.query.as }); ${OWN}`)), mustNot: NOT_CONTROLLED(K) },
      { id: "C04-element-access-identity-write", schemas: S, files: app(H("get", `if (req.query.as) req["user"] = { id: req.query.as }; ${OWN}`)), mustNot: NOT_CONTROLLED(K) },
      { id: "C05-two-level-callee-rewrite", schemas: S, files: app(`function b(r) { if (r.query.as) r.user = { id: r.query.as }; }\nfunction a(r) { b(r); }\n` + H("get", `a(req); ${OWN}`)), mustNot: NOT_CONTROLLED(K) },
      { id: "C06-alias-in-callee", schemas: S, files: app(`function imp(r) { const q = r; if (q.query.as) q.user = { id: q.query.as }; }\n` + H("get", `imp(req); ${OWN}`)), mustNot: NOT_CONTROLLED(K) },
      { id: "C07-catch-next-without-return", schemas: S, files: app(H("delete", `try { const n = await prisma.note.findUnique({ where: { id: req.params.id } }); if (n.userId !== req.user.id) throw new Error("x"); } catch (e) { next(e); } await prisma.note.delete({ where: { id: req.params.id } }); res.json({});`)), mustNot: NOT_CONTROLLED("DELETE /n/:id note.delete") },
      { id: "C08-route-param-vs-literal-auth", schemas: S, files: app(`app.use("/me", auth);\napp.get("/:slug/n/:id", async (req, res) => { res.json(await prisma.note.findFirst({ where: { id: req.params.id, userId: req.user?.id } })); });`), mustNot: NOT_CONTROLLED("GET /:slug/n/:id note.findFirst") },
      { id: "C09-route-param-vs-literal-role", schemas: S, files: M(`app.use(auth);\napp.use("/admin", requireRole3("admin"));\napp.get("/:section/n/:id", async (req, res) => { res.json(await prisma.note.findUnique({ where: { id: req.params.id } })); });`), mustNotStatus: { "GET /:section/n/:id note.findUnique": ["OUT_OF_SCOPE_PROVEN", "CONTROLLED"] } },
      { id: "C10-aliased-req-in-handler", schemas: S, files: app(H("get", `const r2 = req; if (req.query.as) r2.user = { id: req.query.as }; ${OWN}`)), mustNot: NOT_CONTROLLED(K) },
      { id: "C11-destructured-principal-mutated", schemas: S, files: app(H("get", `const { user } = req; if (req.query.as) user.id = req.query.as; ${OWN}`)), mustNot: NOT_CONTROLLED(K) },
    ];
  })(),

  // ---- quarta rodada (revisão adversarial do ORÁCULO, 14/out/2026): leitura pública por desenho ----
  { id: "D01-read-filtered-published", schemas: S, files: app(H("get", `res.json(await prisma.note.findFirst({ where: { id: req.params.id, published: true } }));`)), mustNotStatus: { "GET /n/:id note.findFirst": ["VULNERABLE"] } },
  { id: "D02-write-with-extra-filter-still-vulnerable", schemas: S, files: app(H("delete", `res.json(await prisma.note.deleteMany({ where: { id: req.params.id, archived: false } }));`)), expect: { "DELETE /n/:id note.deleteMany": "VULNERABLE_NO_OWNERSHIP_CHECK" } },

  // ---- queda ----
  { id: "A37-namespace-member-external", schemas: S, files: { ...app(`app.get("/n/:id", auth, ctrl.getNote);`, `import * as ctrl from "./ctrl";`), "src/ctrl.ts": `import { getNote } from "some-pkg";\n` }, noCrash: true },
];
