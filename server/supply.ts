import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { gunzipSync, gzipSync } from "node:zlib";
import { judge, UNKNOWN, type LicencePolicy, type Verdict } from "./licence.ts";
import { parseSbom, SbomError, type Pkg, type SbomFormat } from "./sbom.ts";

export type ProblemCode =
  "invalid-token" | "invalid-json" | "invalid-body" | "invalid-sbom" | "not-found" | "not-configured" | "payload-too-large" | "internal-error";

export class SupplyError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type Rule = "signature" | "sbom" | "provenance" | "licences";
export const RULES: Rule[] = ["signature", "sbom", "provenance", "licences"];
const WAIVES = [...RULES, "all"] as const;

/** What every image must show before it may run (ADR 0043). */
export interface Policy {
  requireSignature: boolean;
  /** Regular expressions the signer's identity must match one of. Empty: any identity. */
  allowedIdentities: string[];
  /** Exact issuers. Empty: any issuer. */
  allowedIssuers: string[];
  requireSbom: boolean;
  requireProvenance: boolean;
  /** SLSA build level, 0 to 4. */
  minProvenanceLevel: number;
  /** SPDX ids. Empty: any licence that is not denied. */
  licenceAllow: string[];
  licenceDeny: string[];
}

export const DEFAULT_POLICY: Policy = {
  requireSignature: true,
  allowedIdentities: [],
  allowedIssuers: [],
  requireSbom: true,
  requireProvenance: false,
  minProvenanceLevel: 0,
  licenceAllow: [],
  licenceDeny: [],
};

// Names such as ghcr.io/acme/app or registry:5000/team/app, without tag or digest.
const NAME = /^[a-z0-9][a-z0-9._:/-]{0,254}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const MAX_EXCEPTION_DAYS = 366;
const MAX_LIST = 200;
/** Packages in an answer about one image; the rest are paged. */
const now = () => new Date().toISOString();
const bad = (detail: string) => new SupplyError(422, "invalid-body", detail);
const notFound = (what: string) => new SupplyError(404, "not-found", `${what} does not exist.`);

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}
const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}
export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

const strList = (value: unknown, what: string): string[] => {
  if (!Array.isArray(value) || value.length > MAX_LIST || value.some((v) => typeof v !== "string" || !v.trim() || v.length > 256))
    throw bad(`${what} must be a list of at most ${MAX_LIST} non-empty strings.`);
  return [...new Set((value as string[]).map((v) => v.trim()))];
};

/** Validates a whole policy. Unknown fields are refused, so a typo does not silently loosen the rules. */
export function parsePolicy(body: Record<string, unknown>): Policy {
  const { requireSignature, allowedIdentities, allowedIssuers, requireSbom, requireProvenance, minProvenanceLevel, licenceAllow, licenceDeny, ...rest } = body;
  if (Object.keys(rest).length) throw bad(`Unknown policy fields: ${Object.keys(rest).join(", ")}.`);
  for (const [k, v] of Object.entries({ requireSignature, requireSbom, requireProvenance }))
    if (typeof v !== "boolean") throw bad(`${k} must be true or false.`);
  if (!Number.isInteger(minProvenanceLevel) || (minProvenanceLevel as number) < 0 || (minProvenanceLevel as number) > 4)
    throw bad("minProvenanceLevel must be a whole number from 0 to 4.");
  const identities = strList(allowedIdentities, "allowedIdentities");
  for (const pattern of identities) {
    try {
      new RegExp(pattern);
    } catch {
      throw bad(`allowedIdentities holds a pattern that is not a regular expression: ${pattern}`);
    }
  }
  return {
    requireSignature: requireSignature as boolean,
    allowedIdentities: identities,
    allowedIssuers: strList(allowedIssuers, "allowedIssuers"),
    requireSbom: requireSbom as boolean,
    requireProvenance: requireProvenance as boolean,
    minProvenanceLevel: minProvenanceLevel as number,
    licenceAllow: strList(licenceAllow, "licenceAllow"),
    licenceDeny: strList(licenceDeny, "licenceDeny"),
  };
}

export interface Reason {
  rule: Rule | "unknown-image";
  message: string;
  /** True when an active exception covers it. */
  waived: boolean;
}

interface ImageRow {
  id: string;
  name: string;
  digest: string;
  sbom_format: SbomFormat | null;
  sbom_at: string | null;
  signature_verified: number | null;
  signature_identity: string | null;
  signature_issuer: string | null;
  signature_at: string | null;
  provenance_builder: string | null;
  provenance_repo: string | null;
  provenance_commit: string | null;
  provenance_level: number | null;
  provenance_at: string | null;
  created_at: string;
  updated_at: string;
}

const ref = (name: string, digest: string) => `${name}@${digest}`;

export function createSupply(db: DatabaseSync) {
  const rowOf = (id: string) => {
    const r = db
      .prepare(
        "SELECT id, name, digest, sbom_format, sbom_at, signature_verified, signature_identity, signature_issuer, signature_at, provenance_builder, provenance_repo, provenance_commit, provenance_level, provenance_at, created_at, updated_at FROM images WHERE id = ?",
      )
      .get(id) as ImageRow | undefined;
    if (!r) throw notFound("The image");
    return r;
  };

  function policy(): Policy {
    const v = (db.prepare("SELECT value FROM settings WHERE key = 'policy'").get() as { value: string } | undefined)?.value;
    return v ? { ...DEFAULT_POLICY, ...(JSON.parse(v) as Partial<Policy>) } : { ...DEFAULT_POLICY };
  }

  const activeExceptions = (name: string, digest: string) =>
    db.prepare("SELECT * FROM exceptions WHERE name = ? AND (digest IS NULL OR digest = ?) AND expires_at > ?").all(name, digest, now()) as Array<{
      rule: string;
    }>;

  /** Licences of an image as the distinct expressions with how many packages carry each, judged by the policy. */
  function licences(imageId: string, p: LicencePolicy) {
    const rows = db.prepare("SELECT licence, COUNT(*) AS n FROM packages WHERE image_id = ? GROUP BY licence ORDER BY n DESC, licence").all(imageId) as Array<{
      licence: string | null;
      n: number;
    }>;
    return rows.map((r) => ({ licence: r.licence ?? UNKNOWN, packages: r.n, verdict: judge(r.licence, p) as Verdict }));
  }

  /** Everything the policy has against an image, each marked as waived or not. The image is allowed when nothing is left. */
  function evaluate(r: ImageRow) {
    const p = policy();
    const found: Array<Omit<Reason, "waived">> = [];
    if (p.requireSignature) {
      if (r.signature_verified === null) found.push({ rule: "signature", message: "No signature check has been reported for this image." });
      else if (r.signature_verified === 0) found.push({ rule: "signature", message: "The signature did not verify." });
      else {
        if (p.allowedIdentities.length && !p.allowedIdentities.some((x) => new RegExp(x).test(r.signature_identity ?? "")))
          found.push({ rule: "signature", message: `Signed by ${r.signature_identity ?? "an unknown identity"}, which the policy does not allow.` });
        if (p.allowedIssuers.length && !p.allowedIssuers.includes(r.signature_issuer ?? ""))
          found.push({ rule: "signature", message: `The signer's issuer ${r.signature_issuer ?? "(none)"} is not allowed.` });
      }
    }
    if (p.requireSbom && !r.sbom_at) found.push({ rule: "sbom", message: "No SBOM has been stored for this image." });
    if (p.requireProvenance || p.minProvenanceLevel > 0) {
      if (r.provenance_at === null) found.push({ rule: "provenance", message: "No provenance has been reported for this image." });
      else if ((r.provenance_level ?? 0) < p.minProvenanceLevel)
        found.push({ rule: "provenance", message: `Provenance is SLSA level ${r.provenance_level ?? 0}; the policy needs ${p.minProvenanceLevel}.` });
    }
    if (r.sbom_at && (p.licenceAllow.length || p.licenceDeny.length)) {
      const bad = licences(r.id, { allow: p.licenceAllow, deny: p.licenceDeny }).filter((l) => l.verdict === "denied");
      if (bad.length)
        found.push({
          rule: "licences",
          message: `${bad.reduce((a, l) => a + l.packages, 0)} packages carry licences the policy does not allow: ${bad
            .slice(0, 5)
            .map((l) => l.licence)
            .join(", ")}${bad.length > 5 ? ", …" : ""}.`,
        });
    }
    const waivers = new Set(activeExceptions(r.name, r.digest).map((e) => e.rule));
    const reasons: Reason[] = found.map((f) => ({ ...f, waived: waivers.has("all") || waivers.has(f.rule) }));
    return { allowed: reasons.every((x) => x.waived), reasons };
  }

  function present(r: ImageRow) {
    const e = evaluate(r);
    return {
      id: r.id,
      name: r.name,
      digest: r.digest,
      allowed: e.allowed,
      reasons: e.reasons,
      sbom: r.sbom_at
        ? {
            format: r.sbom_format!,
            at: r.sbom_at,
            packages: (db.prepare("SELECT COUNT(*) AS n FROM packages WHERE image_id = ?").get(r.id) as { n: number }).n,
          }
        : null,
      signature: r.signature_at
        ? { verified: r.signature_verified === 1, identity: r.signature_identity, issuer: r.signature_issuer, at: r.signature_at }
        : null,
      provenance: r.provenance_at
        ? { builder: r.provenance_builder, sourceRepo: r.provenance_repo, sourceCommit: r.provenance_commit, level: r.provenance_level, at: r.provenance_at }
        : null,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    };
  }

  function presentException(e: Record<string, any>) {
    return {
      id: e.id as string,
      name: e.name as string,
      digest: (e.digest as string | null) ?? null,
      rule: e.rule as (typeof WAIVES)[number],
      reason: e.reason as string,
      by: (e.created_by as string | null) ?? null,
      createdAt: e.created_at as string,
      expiresAt: e.expires_at as string,
      active: (e.expires_at as string) > now(),
    };
  }

  const text = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);

  return {
    /**
     * Stores what CI knows about an image: any of an SBOM, the result of its own signature check and a provenance
     * summary. What is not sent is left as it was. Nothing here is verified cryptographically (ADR 0043).
     */
    ingest(params: { name: string | null; digest: string | null }, raw: Buffer) {
      const { name, digest } = params;
      if (!name || !NAME.test(name)) throw bad("name is required: the image without tag or digest, such as ghcr.io/acme/app.");
      if (!digest || !DIGEST.test(digest)) throw bad("digest is required: sha256: and 64 hex digits.");
      let body: Record<string, any>;
      try {
        const parsed = JSON.parse(raw.toString("utf8")) as unknown;
        if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
        body = parsed as Record<string, any>;
      } catch {
        throw new SupplyError(422, "invalid-json", "The body must be a JSON object: { sbom?, signature?, provenance? }.");
      }
      const { sbom, signature, provenance, ...rest } = body;
      if (Object.keys(rest).length || (sbom === undefined && signature === undefined && provenance === undefined))
        throw bad("Expected { sbom?, signature?, provenance? } with at least one of them.");

      let packages: Pkg[] | undefined;
      let format: SbomFormat | undefined;
      if (sbom !== undefined) {
        try {
          ({ format, packages } = parseSbom(sbom));
        } catch (err) {
          if (err instanceof SbomError) throw new SupplyError(422, "invalid-sbom", err.message);
          throw err;
        }
      }
      if (signature !== undefined) {
        if (
          signature === null ||
          typeof signature !== "object" ||
          typeof signature.verified !== "boolean" ||
          (signature.identity != null && typeof signature.identity !== "string") ||
          (signature.issuer != null && typeof signature.issuer !== "string")
        )
          throw bad("signature must be { verified, identity?, issuer? }.");
      }
      if (provenance !== undefined) {
        const l = provenance?.level;
        if (provenance === null || typeof provenance !== "object" || !Number.isInteger(l) || l < 0 || l > 4)
          throw bad("provenance must be { builder?, sourceRepo?, sourceCommit?, level } with level from 0 to 4.");
      }

      const at = now();
      db.exec("BEGIN IMMEDIATE");
      try {
        let id = (db.prepare("SELECT id FROM images WHERE name = ? AND digest = ?").get(name, digest) as { id: string } | undefined)?.id;
        const created = !id;
        if (!id) {
          id = randomUUID();
          db.prepare("INSERT INTO images (id, name, digest, created_at, updated_at) VALUES (?, ?, ?, ?, ?)").run(id, name, digest, at, at);
        }
        if (packages) {
          db.prepare("DELETE FROM packages WHERE image_id = ?").run(id);
          const insert = db.prepare("INSERT INTO packages (image_id, name, version, purl, licence) VALUES (?, ?, ?, ?, ?)");
          for (const p of packages) insert.run(id, p.name, p.version, p.purl, p.licence);
          db.prepare("UPDATE images SET sbom = ?, sbom_format = ?, sbom_at = ? WHERE id = ?").run(gzipSync(Buffer.from(JSON.stringify(sbom))), format!, at, id);
        }
        if (signature)
          db.prepare("UPDATE images SET signature_verified = ?, signature_identity = ?, signature_issuer = ?, signature_at = ? WHERE id = ?").run(
            signature.verified ? 1 : 0,
            text(signature.identity, 512),
            text(signature.issuer, 512),
            at,
            id,
          );
        if (provenance)
          db.prepare(
            "UPDATE images SET provenance_builder = ?, provenance_repo = ?, provenance_commit = ?, provenance_level = ?, provenance_at = ? WHERE id = ?",
          ).run(text(provenance.builder, 512), text(provenance.sourceRepo, 512), text(provenance.sourceCommit, 128), provenance.level, at, id);
        db.prepare("UPDATE images SET updated_at = ? WHERE id = ?").run(at, id);
        db.exec("COMMIT");
        return { created, image: present(rowOf(id)) };
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },

    listImages(filter: { q?: string; allowed?: boolean }, cursor: string | undefined, limit: number): Page<ReturnType<typeof present>> {
      const where: string[] = [];
      const args: SQLInputValue[] = [];
      if (filter.q) {
        where.push("(name LIKE ? ESCAPE '\\' OR digest LIKE ? ESCAPE '\\')");
        const like = `%${filter.q.replace(/[\\%_]/g, "\\$&")}%`;
        args.push(like, like);
      }
      // The state depends on the policy of the moment, so it is worked out per image and filtered here.
      const rows = db
        .prepare(`SELECT id FROM images ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY updated_at DESC, id`)
        .all(...args) as Array<{ id: string }>;
      const offset = decodeCursor(cursor);
      const items: ReturnType<typeof present>[] = [];
      let seen = 0;
      let next: number | undefined;
      for (const { id } of rows) {
        const img = present(rowOf(id));
        if (filter.allowed !== undefined && img.allowed !== filter.allowed) continue;
        if (seen++ < offset) continue;
        if (items.length === limit) {
          next = offset + limit;
          break;
        }
        items.push(img);
      }
      return { items, ...(next !== undefined && { nextCursor: encodeCursor(next) }) };
    },

    image(id: string) {
      const r = rowOf(id);
      return { ...present(r), licences: r.sbom_at ? licences(id, { allow: policy().licenceAllow, deny: policy().licenceDeny }) : [] };
    },

    packages(id: string, q: string | undefined, cursor: string | undefined, limit: number) {
      rowOf(id);
      const offset = decodeCursor(cursor);
      const like = q ? `%${q.replace(/[\\%_]/g, "\\$&")}%` : "%";
      const rows = db
        .prepare("SELECT name, version, purl, licence FROM packages WHERE image_id = ? AND name LIKE ? ESCAPE '\\' ORDER BY name, version LIMIT ? OFFSET ?")
        .all(id, like, limit + 1, offset) as Array<{ name: string; version: string; purl: string | null; licence: string | null }>;
      return {
        items: rows.slice(0, limit).map((p) => ({ name: p.name, version: p.version, purl: p.purl, licence: p.licence })),
        ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
      } satisfies Page<unknown>;
    },

    sbom(id: string) {
      rowOf(id);
      const r = db.prepare("SELECT sbom, sbom_format FROM images WHERE id = ?").get(id) as { sbom: Uint8Array | null; sbom_format: SbomFormat | null };
      if (!r.sbom) throw notFound("The SBOM");
      return { body: gunzipSync(r.sbom), format: r.sbom_format! };
    },

    deleteImage(id: string) {
      if (db.prepare("DELETE FROM images WHERE id = ?").run(id).changes === 0) throw notFound("The image");
    },

    /** The answer an admission webhook or a pipeline asks for. An image nobody reported on is denied. */
    check(name: string | null, digest: string | null) {
      if (!name || !NAME.test(name)) throw bad("name is required: the image without tag or digest.");
      if (!digest || !DIGEST.test(digest)) throw bad("digest is required: sha256: and 64 hex digits.");
      const r = db.prepare("SELECT id FROM images WHERE name = ? AND digest = ?").get(name, digest) as { id: string } | undefined;
      if (!r)
        return {
          allowed: false,
          image: null,
          reasons: [{ rule: "unknown-image" as const, message: `Nothing is known about ${ref(name, digest)}; CI must report it first.`, waived: false }],
        };
      const e = evaluate(rowOf(r.id));
      return { allowed: e.allowed, image: { id: r.id }, reasons: e.reasons };
    },

    /** Which images contain a package, optionally at one version. */
    whereUsed(name: string | null, version: string | null, cursor: string | undefined, limit: number) {
      if (!name?.trim() || name.length > 256) throw bad("name is required: the package, such as openssl.");
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare(
          `SELECT p.name AS package, p.version, p.purl, p.licence, i.id, i.name AS image, i.digest FROM packages p JOIN images i ON i.id = p.image_id
           WHERE p.name = ? ${version ? "AND p.version = ?" : ""} ORDER BY i.name, i.digest, p.version LIMIT ? OFFSET ?`,
        )
        .all(...([name.trim(), ...(version ? [version] : []), limit + 1, offset] as SQLInputValue[])) as Array<Record<string, string | null>>;
      return {
        items: rows.slice(0, limit).map((r) => ({
          image: { id: r.id!, name: r.image!, digest: r.digest! },
          package: r.package!,
          version: r.version!,
          purl: r.purl ?? null,
          licence: r.licence ?? null,
        })),
        ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
      } satisfies Page<unknown>;
    },

    policy,
    setPolicy(body: Record<string, unknown>) {
      const p = parsePolicy(body);
      db.prepare("INSERT INTO settings (key, value) VALUES ('policy', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(JSON.stringify(p));
      return p;
    },

    listExceptions: () => (db.prepare("SELECT * FROM exceptions ORDER BY expires_at").all() as Array<Record<string, any>>).map(presentException),
    createException(body: Record<string, unknown>, by: string) {
      const { name, digest, rule, reason, expiresAt, ...rest } = body;
      if (Object.keys(rest).length || typeof name !== "string" || !NAME.test(name))
        throw bad("Expected { name, digest?, rule, reason, expiresAt }; name is the image without tag or digest.");
      if (digest != null && (typeof digest !== "string" || !DIGEST.test(digest))) throw bad("digest must be sha256: and 64 hex digits.");
      if (typeof rule !== "string" || !WAIVES.includes(rule as (typeof WAIVES)[number])) throw bad(`rule must be one of ${WAIVES.join(", ")}.`);
      // A decision without a reason is lost the day its author leaves (ADR 0043).
      if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500) throw bad("reason is required: 3 to 500 characters.");
      const t = typeof expiresAt === "string" ? Date.parse(expiresAt) : NaN;
      if (Number.isNaN(t) || t <= Date.now()) throw bad("expiresAt must be a date in the future.");
      if (t > Date.now() + MAX_EXCEPTION_DAYS * 86_400_000) throw bad(`expiresAt must be within ${MAX_EXCEPTION_DAYS} days.`);
      const id = randomUUID();
      db.prepare("INSERT INTO exceptions (id, name, digest, rule, reason, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(
        id,
        name,
        (digest as string | null | undefined) ?? null,
        rule,
        reason.trim(),
        by,
        now(),
        new Date(t).toISOString(),
      );
      return presentException(db.prepare("SELECT * FROM exceptions WHERE id = ?").get(id) as Record<string, any>);
    },
    deleteException(id: string) {
      if (db.prepare("DELETE FROM exceptions WHERE id = ?").run(id).changes === 0) throw notFound("The exception");
    },

    /**
     * What the overview draws besides the summary: images first seen in each of the last 12 weeks, how many carry
     * each kind of evidence, the newest images with their verdict, and the packages most images contain.
     */
    overview() {
      const DAY = 86_400_000;
      const today = Math.floor(Date.now() / DAY) * DAY;
      const first = today + DAY - 12 * 7 * DAY;
      const weeks = Array.from({ length: 12 }, (_, i) => ({ week: new Date(first + i * 7 * DAY).toISOString().slice(0, 10), images: 0 }));
      for (const r of db.prepare("SELECT created_at FROM images WHERE created_at >= ?").all(new Date(first).toISOString()) as Array<{ created_at: string }>) {
        const w = weeks[Math.floor((Date.parse(r.created_at) - first) / (7 * DAY))];
        if (w) w.images++;
      }
      const evidence = db
        .prepare(
          "SELECT COUNT(*) AS images, COALESCE(SUM(signature_verified = 1), 0) AS signed, COALESCE(SUM(sbom_at IS NOT NULL), 0) AS sbom, COALESCE(SUM(provenance_at IS NOT NULL), 0) AS provenance FROM images",
        )
        .get() as { images: number; signed: number; sbom: number; provenance: number };
      const recent = (db.prepare("SELECT id FROM images ORDER BY updated_at DESC, rowid DESC LIMIT 8").all() as Array<{ id: string }>).map(({ id }) => {
        const r = rowOf(id);
        const e = evaluate(r);
        return {
          id,
          name: r.name,
          digest: r.digest,
          allowed: e.allowed,
          rules: [...new Set(e.reasons.filter((x) => !x.waived).map((x) => x.rule))],
          updatedAt: r.updated_at,
        };
      });
      const topPackages = db
        .prepare("SELECT name, COUNT(DISTINCT image_id) AS images FROM packages GROUP BY name ORDER BY images DESC, name LIMIT 8")
        .all() as Array<{ name: string; images: number }>;
      return { weeks, evidence, recent, topPackages };
    },

    summary() {
      const ids = db.prepare("SELECT id FROM images").all() as Array<{ id: string }>;
      let allowed = 0;
      let waived = 0;
      const deniedBy = Object.fromEntries(RULES.map((r) => [r, 0])) as Record<Rule, number>;
      for (const { id } of ids) {
        const e = evaluate(rowOf(id));
        if (e.allowed) allowed++;
        if (e.allowed && e.reasons.length) waived++;
        for (const rule of new Set(e.reasons.filter((x) => !x.waived).map((x) => x.rule))) if (rule !== "unknown-image") deniedBy[rule]++;
      }
      // The licences most packages carry, over every image, judged by the policy.
      const p = policy();
      const topLicences = (
        db.prepare("SELECT licence, COUNT(*) AS n FROM packages GROUP BY licence ORDER BY n DESC, licence LIMIT 8").all() as Array<{
          licence: string | null;
          n: number;
        }>
      ).map((r) => ({ licence: r.licence ?? UNKNOWN, packages: r.n, verdict: judge(r.licence, { allow: p.licenceAllow, deny: p.licenceDeny }) as Verdict }));
      const withoutSbom = (db.prepare("SELECT COUNT(*) AS n FROM images WHERE sbom_at IS NULL").get() as { n: number }).n;
      const exceptions = (db.prepare("SELECT COUNT(*) AS n FROM exceptions WHERE expires_at > ?").get(now()) as { n: number }).n;
      const packages = (db.prepare("SELECT COUNT(*) AS n FROM packages").get() as { n: number }).n;
      return {
        images: ids.length,
        allowed,
        denied: ids.length - allowed,
        allowedByException: waived,
        withoutSbom,
        activeExceptions: exceptions,
        packages,
        deniedBy,
        licences: topLicences,
      };
    },
  };
}

export type Supply = ReturnType<typeof createSupply>;
