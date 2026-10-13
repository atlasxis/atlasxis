// Atlasxis — fixtures Express + Prisma, ground truth por construção.
// As formas imitam um backend real (camadas controller → service → repositório, middleware JWT que
// grava req.user / req.professional / req.admin, asyncHandler, singletons de classe, this.db, tx),
// sem copiar código de terceiros. Chave de cada acesso: "<VERBO> <caminho completo> <modelo>.<op>".

const SCHEMA = `
model User { id String @id  appointments Appointment[] }
model Professional { id String @id  carePlans CarePlan[] }
model AdminUser { id String @id  role String }
model Appointment {
  id String @id
  userId String
  user User @relation(fields: [userId], references: [id])
  professionalId String
  professional Professional @relation(fields: [professionalId], references: [id])
}
model Payment {
  id String @id
  userId String
  user User @relation(fields: [userId], references: [id])
  appointmentId String
  appointment Appointment @relation(fields: [appointmentId], references: [id])
  status String
}
model CarePlan {
  id String @id
  professionalId String
  professional Professional @relation(fields: [professionalId], references: [id])
}
model Goal {
  id String @id
  carePlanId String
  carePlan CarePlan @relation(fields: [carePlanId], references: [id])
}
model Service { id String @id  name String }
`;

const PRISMA = `import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export default prisma;
`;

const SESSION = `import jwt from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";
export function authenticateUser(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "missing token" });
  try {
    const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET!) as any;
    (req as any).user = { id: payload.sub, role: "USER" };
    return next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}
export function authenticateProfessional(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "missing token" });
  const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET!) as any;
  (req as any).professional = { id: payload.sub };
  return next();
}
export async function authenticateAdmin(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "missing token" });
  const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET!) as any;
  (req as any).admin = { id: payload.sub, role: payload.role };
  return next();
}
export function optionalAuth(req: Request, _res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (header) {
    try { const payload = jwt.verify(header.slice(7), process.env.JWT_SECRET!) as any; (req as any).user = { id: payload.sub }; } catch {}
  }
  return next();
}
`;

const RBAC = `export function requireAdmin() {
  return (req: any, res: any, next: any) => {
    if (!req.admin || req.admin.role !== "ADMIN") return res.status(403).json({ error: "forbidden" });
    return next();
  };
}
`;

const ASYNC = `export const asyncHandler = (fn: any) => (req: any, res: any, next: any) => Promise.resolve(fn(req, res, next)).catch(next);
`;

const ERRORS = `export class ForbiddenError extends Error { status = 403; }
export class NotFoundError extends Error { status = 404; }
`;

function project(extra, mount = "") {
  return {
    "src/core/db/prisma.ts": PRISMA,
    "src/core/middlewares/session.ts": SESSION,
    "src/core/middlewares/rbac.ts": RBAC,
    "src/core/http/asyncHandler.ts": ASYNC,
    "src/core/http/errors.ts": ERRORS,
    "src/app.ts": `import express from "express";\nimport routes from "./routes";\nconst app = express();\napp.use("/v1", routes);\nexport default app;\n`,
    "src/routes.ts": `import { Router } from "express";\n${mount}\nexport default router;\n`,
    ...extra,
  };
}

const MOUNT_APPTS = `import appointmentsRoutes from "./modules/appointments/appointments.routes";\nconst router = Router();\nrouter.use("/appointments", appointmentsRoutes);`;
const apptRoutes = (line) => `import { Router } from "express";\nimport { authenticateUser, authenticateProfessional, optionalAuth } from "../../core/middlewares/session";\nimport * as ctrl from "./appointments.controller";\nconst router = Router();\n${line}\nexport default router;\n`;
const apptController = (body) => `import { asyncHandler } from "../../core/http/asyncHandler";\nimport * as service from "./appointments.service";\n${body}\n`;
const apptService = (body) => `import prisma from "../../core/db/prisma";\nimport { ForbiddenError, NotFoundError } from "../../core/http/errors";\n${body}\n`;

const APPT = (routeLine, controller, service, extra = {}) => project({
  "src/modules/appointments/appointments.routes.ts": apptRoutes(routeLine),
  "src/modules/appointments/appointments.controller.ts": apptController(controller),
  "src/modules/appointments/appointments.service.ts": apptService(service),
  ...extra,
}, MOUNT_APPTS);

const GET_BY_ID = `export const getById = asyncHandler(async (req, res) => {\n  const { id } = req.params;\n  const appointment = await service.getById(id, (req as any).user.id);\n  res.json(appointment);\n});`;

export const SCHEMAS = { "prisma/schema.prisma": SCHEMA };

export const EXPRESS_CASES = [
  {
    id: "E01-owner-filter-in-service", kind: "positive",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `export async function getById(id: string, userId: string) {\n  return prisma.appointment.findFirst({ where: { id, userId } });\n}`),
    expect: { "GET /v1/appointments/:id appointment.findFirst": "CONTROLLED_SELF_SCOPE" },
    mutate: [{ name: "remove owner filter", from: "where: { id, userId }", to: "where: { id }" }],
  },
  {
    id: "E02-idor-no-check", kind: "positive",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `export async function getById(id: string, userId: string) {\n  return prisma.appointment.findUnique({ where: { id } });\n}`),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "VULNERABLE_NO_OWNERSHIP_CHECK" },
    mutate: [{ name: "add owner filter", from: "where: { id }", to: "where: { id, userId }" }],
  },
  {
    id: "E03-post-read-gate-then-write", kind: "positive",
    files: APPT(`router.delete("/:id", authenticateUser, ctrl.remove);`, `export const remove = asyncHandler(async (req, res) => {\n  await service.remove(req.params.id, (req as any).user.id);\n  res.status(204).end();\n});`, `export async function remove(id: string, userId: string) {\n  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (!appt) throw new NotFoundError("not found");\n  if (appt.userId !== userId) throw new ForbiddenError("forbidden");\n  await prisma.appointment.delete({ where: { id } });\n}`),
    expect: { "DELETE /v1/appointments/:id appointment.delete": "CONTROLLED_POST_READ_GATE", "DELETE /v1/appointments/:id appointment.findUnique": "CONTROLLED_POST_READ_GATE" },
    mutate: [{ name: "remove gate", from: `  if (appt.userId !== userId) throw new ForbiddenError("forbidden");\n`, to: "" }],
  },
  {
    id: "E04-helper-gate", kind: "positive",
    files: APPT(`router.delete("/:id", authenticateUser, ctrl.remove);`, `export const remove = asyncHandler(async (req, res) => {\n  await service.remove(req.params.id, (req as any).user.id);\n  res.status(204).end();\n});`, `async function ensureAccess(id: string, userId: string) {\n  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (!appt || appt.userId !== userId) throw new ForbiddenError("forbidden");\n  return appt;\n}\nexport async function remove(id: string, userId: string) {\n  await ensureAccess(id, userId);\n  await prisma.appointment.delete({ where: { id } });\n}`),
    expect: { "DELETE /v1/appointments/:id appointment.delete": "CONTROLLED_OWNERSHIP_HELPER" },
    mutate: [{ name: "helper stops comparing owner", from: "if (!appt || appt.userId !== userId) throw", to: "if (!appt) throw" }],
  },
  {
    id: "E05-write-before-gate", kind: "adversarial",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `export async function getById(id: string, userId: string) {\n  await prisma.payment.updateMany({ where: { appointmentId: id, status: "PENDING" }, data: { status: "EXPIRED" } });\n  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (!appt || appt.userId !== userId) throw new ForbiddenError("forbidden");\n  return appt;\n}`),
    expect: { "GET /v1/appointments/:id payment.updateMany": "VULNERABLE_NO_OWNERSHIP_CHECK", "GET /v1/appointments/:id appointment.findUnique": "CONTROLLED_POST_READ_GATE" },
    mutate: [{ name: "move gate before write", keys: ["GET /v1/appointments/:id payment.updateMany"], from: `  await prisma.payment.updateMany({ where: { appointmentId: id, status: "PENDING" }, data: { status: "EXPIRED" } });\n  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (!appt || appt.userId !== userId) throw new ForbiddenError("forbidden");\n`, to: `  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (!appt || appt.userId !== userId) throw new ForbiddenError("forbidden");\n  await prisma.payment.updateMany({ where: { appointmentId: id, status: "PENDING" }, data: { status: "EXPIRED" } });\n` }],
  },
  {
    id: "E06-unauthenticated-catalog", kind: "negative",
    files: APPT(`router.get("/services/:id", ctrl.getService);`, `export const getService = asyncHandler(async (req, res) => {\n  res.json(await service.getService(req.params.id));\n});`, `export async function getService(id: string) {\n  return prisma.service.findUnique({ where: { id } });\n}`),
    expect: { "GET /v1/appointments/services/:id service.findUnique": "INSUFFICIENT_UNAUTHENTICATED_ROUTE" },
    mustNot: { "GET /v1/appointments/services/:id service.findUnique": "VULNERABLE" },
  },
  {
    id: "E07-optional-auth-is-not-auth", kind: "adversarial",
    files: APPT(`router.get("/:id", optionalAuth, ctrl.getById);`, GET_BY_ID, `export async function getById(id: string, userId: string) {\n  return prisma.appointment.findUnique({ where: { id } });\n}`),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "INSUFFICIENT_UNAUTHENTICATED_ROUTE" },
    mustNot: { "GET /v1/appointments/:id appointment.findUnique": "VULNERABLE" },
  },
  {
    id: "E08-router-level-auth-gate", kind: "positive",
    files: project({
      "src/modules/care/care.routes.ts": `import { Router } from "express";\nimport { authenticateProfessional } from "../../core/middlewares/session";\nimport careController from "./care.controller";\nconst router = Router();\nrouter.use(authenticateProfessional);\nrouter.delete("/:id", careController.remove);\nexport default router;\n`,
      "src/modules/care/care.controller.ts": `import careService from "./care.service";\nclass CareController {\n  remove = async (req: any, res: any, next: any) => {\n    try {\n      await careService.remove(req.params.id, req.professional.id);\n      res.status(204).end();\n    } catch (err) { next(err); }\n  };\n}\nexport default new CareController();\n`,
      "src/modules/care/care.service.ts": `import prisma from "../../core/db/prisma";\nimport { ForbiddenError } from "../../core/http/errors";\nclass CareService {\n  async remove(id: string, professionalId: string) {\n    const plan = await prisma.carePlan.findUnique({ where: { id } });\n    if (!plan || plan.professionalId !== professionalId) throw new ForbiddenError("forbidden");\n    return prisma.carePlan.delete({ where: { id } });\n  }\n}\nexport default new CareService();\n`,
    }, `import careRoutes from "./modules/care/care.routes";\nconst router = Router();\nrouter.use("/care-plans", careRoutes);`),
    expect: { "DELETE /v1/care-plans/:id carePlan.delete": "CONTROLLED_POST_READ_GATE" },
    mutate: [{ name: "remove gate", from: "if (!plan || plan.professionalId !== professionalId) throw", to: "if (!plan) throw" }],
  },
  {
    id: "E09-auth-registered-after-route", kind: "adversarial",
    files: project({
      "src/modules/care/care.routes.ts": `import { Router } from "express";\nimport { authenticateProfessional } from "../../core/middlewares/session";\nimport { remove } from "./care.controller";\nconst router = Router();\nrouter.delete("/:id", remove);\nrouter.use(authenticateProfessional);\nexport default router;\n`,
      "src/modules/care/care.controller.ts": `import prisma from "../../core/db/prisma";\nexport async function remove(req: any, res: any) {\n  await prisma.carePlan.delete({ where: { id: req.params.id } });\n  res.status(204).end();\n}\n`,
    }, `import careRoutes from "./modules/care/care.routes";\nconst router = Router();\nrouter.use("/care-plans", careRoutes);`),
    expect: { "DELETE /v1/care-plans/:id carePlan.delete": "INSUFFICIENT_UNAUTHENTICATED_ROUTE" },
    mustNot: { "DELETE /v1/care-plans/:id carePlan.delete": "VULNERABLE" },
  },
  {
    id: "E10-mount-level-auth-idor", kind: "positive",
    files: project({
      "src/modules/me/me.routes.ts": `import { Router } from "express";\nimport prisma from "../../core/db/prisma";\nconst router = Router();\nrouter.get("/payments/:id", async (req: any, res: any) => {\n  const payment = await prisma.payment.findUnique({ where: { id: req.params.id } });\n  res.json(payment);\n});\nexport default router;\n`,
    }, `import { authenticateUser } from "./core/middlewares/session";\nimport meRoutes from "./modules/me/me.routes";\nconst router = Router();\nrouter.use("/me", authenticateUser, meRoutes);`),
    expect: { "GET /v1/me/payments/:id payment.findUnique": "VULNERABLE_NO_OWNERSHIP_CHECK" },
    mutate: [{ name: "bind owner", from: "where: { id: req.params.id }", to: "where: { id: req.params.id, userId: req.user.id }" }],
  },
  {
    id: "E11-owner-from-body", kind: "adversarial",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getMine);`, `export const getMine = asyncHandler(async (req, res) => {\n  res.json(await service.getMine(req.params.id, req.body.userId));\n});`, `export async function getMine(id: string, userId: string) {\n  return prisma.appointment.findFirst({ where: { id, userId } });\n}`),
    expect: { "GET /v1/appointments/:id appointment.findFirst": "INSUFFICIENT_IDENTITY_FROM_CLIENT" },
    mustNot: { "GET /v1/appointments/:id appointment.findFirst": "CONTROLLED" },
  },
  {
    id: "E12-model-not-linked-to-principal", kind: "negative",
    files: project({
      "src/modules/goals/goals.routes.ts": `import { Router } from "express";\nimport { authenticateProfessional } from "../../core/middlewares/session";\nimport prisma from "../../core/db/prisma";\nconst router = Router();\nrouter.get("/:id", authenticateProfessional, async (req: any, res: any) => {\n  res.json(await prisma.goal.findUnique({ where: { id: req.params.id } }));\n});\nexport default router;\n`,
    }, `import goalsRoutes from "./modules/goals/goals.routes";\nconst router = Router();\nrouter.use("/goals", goalsRoutes);`),
    expect: { "GET /v1/goals/:id goal.findUnique": "INSUFFICIENT_TRANSITIVE_OWNERSHIP" },
    mustNot: { "GET /v1/goals/:id goal.findUnique": "VULNERABLE" },
  },
  {
    id: "E13-unresolved-call-before-sink", kind: "adversarial",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `import { checkAccess } from "external-acl";\nexport async function getById(id: string, userId: string) {\n  await checkAccess(userId, id);\n  return prisma.appointment.findUnique({ where: { id } });\n}`),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "INSUFFICIENT_GUARD_UNRESOLVED" },
    mustNot: { "GET /v1/appointments/:id appointment.findUnique": "VULNERABLE" },
  },
  {
    id: "E14-gate-only-when-actor-present", kind: "adversarial",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `export async function getById(id: string, userId?: string) {\n  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (userId) {\n    if (!appt || appt.userId !== userId) throw new ForbiddenError("forbidden");\n  }\n  return appt;\n}`),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "INSUFFICIENT_UNRESOLVED_GATING" },
    mustNot: { "GET /v1/appointments/:id appointment.findUnique": "VULNERABLE" },
  },
  {
    id: "E15-admin-role-router", kind: "negative",
    files: project({
      "src/modules/admin/admin.routes.ts": `import { Router } from "express";\nimport prisma from "../../core/db/prisma";\nconst router = Router();\nrouter.delete("/appointments/:id", async (req: any, res: any) => {\n  await prisma.appointment.delete({ where: { id: req.params.id } });\n  res.status(204).end();\n});\nexport default router;\n`,
    }, `import { authenticateAdmin } from "./core/middlewares/session";\nimport { requireAdmin } from "./core/middlewares/rbac";\nimport adminRoutes from "./modules/admin/admin.routes";\nconst router = Router();\nrouter.use("/admin", authenticateAdmin, requireAdmin(), adminRoutes);`),
    expect: { "DELETE /v1/admin/appointments/:id appointment.delete": "OOS_PROVEN_ROLE_MIDDLEWARE" },
    mustNot: { "DELETE /v1/admin/appointments/:id appointment.delete": "VULNERABLE" },
  },
  {
    id: "E16-class-method-bind-owner-filter", kind: "positive",
    files: project({
      "src/modules/payments/payments.routes.ts": `import { Router } from "express";\nimport { authenticateUser } from "../../core/middlewares/session";\nimport paymentsController from "./payments.controller";\nconst router = Router();\nrouter.get("/payments/:id", authenticateUser, paymentsController.get.bind(paymentsController));\nexport default router;\n`,
      "src/modules/payments/payments.controller.ts": `import prisma from "../../core/db/prisma";\nclass PaymentsController {\n  async get(req: any, res: any) {\n    const payment = await prisma.payment.findFirst({ where: { id: req.params.id, userId: req.user.id } });\n    res.json(payment);\n  }\n}\nexport default new PaymentsController();\n`,
    }, `import paymentsRoutes from "./modules/payments/payments.routes";\nconst router = Router();\nrouter.use("/", paymentsRoutes);`),
    expect: { "GET /v1/payments/:id payment.findFirst": "CONTROLLED_SELF_SCOPE" },
    mutate: [{ name: "remove owner filter", from: ", userId: req.user.id", to: "" }],
  },
  {
    id: "E17-dynamic-dispatch", kind: "negative",
    files: project({
      "src/modules/pros/pros.routes.ts": `import { Router } from "express";\nimport { authenticateProfessional } from "../../core/middlewares/session";\nimport prosController from "./pros.controller";\nconst router = Router();\nconst handler = (method: string) => (req: any, res: any, next: any) => (prosController as any)[method](req, res, next);\nrouter.get("/:id", authenticateProfessional, handler("get"));\nexport default router;\n`,
      "src/modules/pros/pros.controller.ts": `import prisma from "../../core/db/prisma";\nexport default { async get(req: any, res: any) { res.json(await prisma.carePlan.findUnique({ where: { id: req.params.id } })); } };\n`,
    }, `import prosRoutes from "./modules/pros/pros.routes";\nconst router = Router();\nrouter.use("/pros", prosRoutes);`),
    mustNot: { "GET /v1/pros/:id carePlan.findUnique": "VULNERABLE" },
    handlerExpect: { "GET /v1/pros/:id": "NOT_ANALYZED" },
  },
  {
    id: "E18-actor-object", kind: "positive",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, `export const getById = asyncHandler(async (req, res) => {\n  res.json(await service.getById(req.params.id, { userId: (req as any).user.id }));\n});`, `export async function getById(id: string, actor: { userId: string }) {\n  return prisma.appointment.findFirst({ where: { id, userId: actor.userId } });\n}`),
    expect: { "GET /v1/appointments/:id appointment.findFirst": "CONTROLLED_SELF_SCOPE" },
    mutate: [{ name: "drop actor binding", from: "where: { id, userId: actor.userId }", to: "where: { id }" }],
  },
  {
    id: "E19-transaction-idor", kind: "positive",
    files: APPT(`router.delete("/:id", authenticateUser, ctrl.remove);`, `export const remove = asyncHandler(async (req, res) => {\n  await service.remove(req.params.id);\n  res.status(204).end();\n});`, `export async function remove(id: string) {\n  await prisma.$transaction(async (tx) => {\n    await tx.appointment.delete({ where: { id } });\n  });\n}`),
    expect: { "DELETE /v1/appointments/:id appointment.delete": "VULNERABLE_NO_OWNERSHIP_CHECK" },
  },
  {
    id: "E20-repository-this-db", kind: "positive",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `import repo from "./appointments.repository";\nexport async function getById(id: string, userId: string) {\n  return repo.find(id);\n}`, {
      "src/modules/appointments/appointments.repository.ts": `import prisma from "../../core/db/prisma";\nclass AppointmentsRepository {\n  private db: any;\n  constructor(db?: any) { this.db = db || prisma; }\n  async find(id: string) { return this.db.appointment.findUnique({ where: { id } }); }\n}\nexport default new AppointmentsRepository();\n`,
    }),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "VULNERABLE_NO_OWNERSHIP_CHECK" },
  },
  {
    id: "E21-raw-sql", kind: "negative",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `export async function getById(id: string, userId: string) {\n  return prisma.$queryRaw\`SELECT * FROM "Appointment" WHERE id = \${id}\`;\n}`),
    mustNot: { "GET /v1/appointments/:id null.$queryRaw": "VULNERABLE" },
  },
  {
    id: "E22-create-with-client-reference", kind: "adversarial",
    files: APPT(`router.post("/:id/payments", authenticateUser, ctrl.pay);`, `export const pay = asyncHandler(async (req, res) => {\n  res.json(await service.pay((req as any).user.id, req.body.appointmentId));\n});`, `export async function pay(userId: string, appointmentId: string) {\n  return prisma.payment.create({ data: { userId, appointmentId, status: "PENDING" } });\n}`),
    expect: { "POST /v1/appointments/:id/payments payment.create": "INSUFFICIENT_CROSS_RESOURCE" },
    mustNot: { "POST /v1/appointments/:id/payments payment.create": "CONTROLLED" },
  },
  {
    id: "E23-merged-identity", kind: "adversarial",
    files: project({
      "src/modules/support/support.routes.ts": `import { Router } from "express";\nimport { authenticateUser, authenticateProfessional } from "../../core/middlewares/session";\nimport prisma from "../../core/db/prisma";\nconst router = Router();\nrouter.get("/:id", authenticateUser, authenticateProfessional, async (req: any, res: any) => {\n  const senderId = req.professional?.id || req.user?.id;\n  res.json(await prisma.appointment.findFirst({ where: { id: req.params.id, userId: senderId } }));\n});\nexport default router;\n`,
    }, `import supportRoutes from "./modules/support/support.routes";\nconst router = Router();\nrouter.use("/support", supportRoutes);`),
    expect: { "GET /v1/support/:id appointment.findFirst": "INSUFFICIENT_RESOURCE_IDENTITY" },
    mustNot: { "GET /v1/support/:id appointment.findFirst": "CONTROLLED" },
  },
  {
    id: "E24-list-own", kind: "positive",
    files: APPT(`router.get("/", authenticateUser, ctrl.list);`, `export const list = asyncHandler(async (req, res) => {\n  res.json(await service.list((req as any).user.id));\n});`, `export async function list(userId: string) {\n  return prisma.appointment.findMany({ where: { userId } });\n}`),
    expect: { "GET /v1/appointments/ appointment.findMany": "CONTROLLED_SELF_SCOPE" },
    mutate: [{ name: "list everything", from: "where: { userId }", to: "where: {}" }],
  },
  // E26-E29: formas reais que a primeira versão errou (20 falsos VULNERABLE no backend real).
  {
    id: "E26-check-only-when-actor-present-derived", kind: "adversarial",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, `export const getById = asyncHandler(async (req, res) => {\n  const actor = (req as any).user || { id: (req as any).professional?.id, role: "PROFESSIONAL" };\n  res.json(await service.getById(req.params.id, actor));\n});`, `async function findById(id: string) { return prisma.appointment.findUnique({ where: { id } }); }\nexport async function getById(id: string, user?: any) {\n  try {\n    const appointment = await findById(id);\n    if (!appointment) throw new NotFoundError("not found");\n    if (user) {\n      const hasAccess = user.role === "ADMIN" || (user.role === "USER" && appointment.userId === user.id);\n      if (!hasAccess) {\n        throw new ForbiddenError("forbidden");\n      }\n    }\n    return appointment;\n  } catch (error) { throw error; }\n}`),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "INSUFFICIENT_UNRESOLVED_GATING" },
    mustNot: { "GET /v1/appointments/:id appointment.findUnique": "VULNERABLE" },
  },
  {
    id: "E27-role-branch-checks", kind: "adversarial",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, `export const getById = asyncHandler(async (req, res) => {\n  res.json(await service.getById(req.params.id, { userId: (req as any).user.id }));\n});`, `export async function getById(id: string, actor?: { userId?: string; adminId?: string }) {\n  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (!appt) throw new NotFoundError("not found");\n  const { userId, adminId } = actor ?? {};\n  if (adminId) {\n    return appt;\n  } else if (userId) {\n    if (appt.userId !== userId) throw new Error("forbidden");\n  }\n  return appt;\n}`),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "INSUFFICIENT_UNRESOLVED_GATING" },
    mustNot: { "GET /v1/appointments/:id appointment.findUnique": "VULNERABLE" },
  },
  {
    id: "E28-admin-principal-only", kind: "negative",
    files: project({
      "src/modules/admin/admin.routes.ts": `import { Router } from "express";\nimport prisma from "../../core/db/prisma";\nconst router = Router();\nrouter.get("/appointments/:id", async (req: any, res: any) => {\n  res.json(await prisma.appointment.findUnique({ where: { id: req.params.id } }));\n});\nexport default router;\n`,
    }, `import { authenticateAdmin } from "./core/middlewares/session";\nimport adminRoutes from "./modules/admin/admin.routes";\nconst router = Router();\nrouter.use("/admin", authenticateAdmin, adminRoutes);`),
    expect: { "GET /v1/admin/appointments/:id appointment.findUnique": "OOS_PROVEN_ROLE_MIDDLEWARE" },
    mustNot: { "GET /v1/admin/appointments/:id appointment.findUnique": "VULNERABLE" },
  },
  {
    id: "E29-derived-owner-compare", kind: "positive",
    files: APPT(`router.get("/:id", authenticateUser, ctrl.getById);`, GET_BY_ID, `export async function getById(id: string, userId: string) {\n  const appt = await prisma.appointment.findUnique({ where: { id } });\n  if (!appt) throw new NotFoundError("not found");\n  const isOwner = appt.userId === userId;\n  if (!isOwner) throw new ForbiddenError("forbidden");\n  return appt;\n}`),
    expect: { "GET /v1/appointments/:id appointment.findUnique": "CONTROLLED_POST_READ_GATE" },
    mutate: [{ name: "compare a non-owner field", from: "appt.userId === userId", to: "appt.status === userId" }],
  },
  {
    id: "E30-admin-attribution-and-target", kind: "negative",
    files: project({
      "src/modules/admin/admin.routes.ts": `import { Router } from "express";\nimport prisma from "../../core/db/prisma";\nconst router = Router();\nrouter.post("/notes/:userId", async (req: any, res: any) => {\n  await prisma.appointment.updateMany({ where: { userId: req.params.userId }, data: { status: "CANCELLED" } });\n  res.json(await prisma.payment.create({ data: { userId: req.params.userId, appointmentId: req.body.appointmentId, createdBy: req.admin.id } }));\n});\nexport default router;\n`,
    }, `import { authenticateAdmin } from "./core/middlewares/session";\nimport adminRoutes from "./modules/admin/admin.routes";\nconst router = Router();\nrouter.use("/admin", authenticateAdmin, adminRoutes);`),
    expect: { "POST /v1/admin/notes/:userId appointment.updateMany": "OOS_PROVEN_ROLE_MIDDLEWARE", "POST /v1/admin/notes/:userId payment.create": "OOS_PROVEN_ROLE_MIDDLEWARE" },
    mustNot: { "POST /v1/admin/notes/:userId payment.create": "CONTROLLED" },
  },
  {
    id: "E25-unmounted-router", kind: "adversarial",
    files: project({
      "src/modules/orphan/orphan.routes.ts": `import { Router } from "express";\nimport prisma from "../../core/db/prisma";\nconst router = Router();\nrouter.get("/:id", async (req: any, res: any) => {\n  res.json(await prisma.payment.findUnique({ where: { id: req.params.id } }));\n});\nexport default router;\n`,
    }, `const router = Router();`),
    mustNot: { "GET /:id payment.findUnique": "VULNERABLE" },
  },
];
