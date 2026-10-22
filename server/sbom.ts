export type SbomFormat = "cyclonedx-json" | "spdx-json";

export interface Pkg {
  name: string;
  version: string;
  purl: string | null;
  /** SPDX expression, or the name a tool gave. Null when nobody said. */
  licence: string | null;
}

export class SbomError extends Error {}

type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);

/** Most packages one image may list. A distribution image has a few hundred; a monorepo bundle a few tens of thousands. */
export const MAX_PACKAGES = 100_000;

/** CycloneDX writes `licenses` as a list of `{license:{id|name}}` or one `{expression}`; the list means "and". */
function cdxLicence(licenses: unknown): string | null {
  if (!Array.isArray(licenses)) return null;
  const parts: string[] = [];
  for (const l of licenses) {
    if (!isObj(l)) continue;
    const e = str(l.expression, 256);
    const id = isObj(l.license) ? (str(l.license.id, 128) ?? str(l.license.name, 128)) : null;
    const one = e ?? id;
    if (one) parts.push(one);
  }
  // Several entries mean all of them apply; an entry that is itself an expression keeps its own grouping.
  return parts.length ? (parts.length > 1 ? parts.map((x) => (/\s(?:AND|OR)\s/i.test(x) ? `(${x})` : x)).join(" AND ") : parts[0]!) : null;
}

function spdxLicence(p: Obj): string | null {
  for (const key of ["licenseConcluded", "licenseDeclared"]) {
    const v = str(p[key], 256);
    if (v && !/^(NOASSERTION|NONE)$/i.test(v)) return v;
  }
  return null;
}

/** Reads the packages out of a CycloneDX or SPDX JSON SBOM. */
export function parseSbom(body: unknown): { format: SbomFormat; packages: Pkg[] } {
  if (!isObj(body)) throw new SbomError("The SBOM must be a JSON object.");
  const out: Pkg[] = [];
  const seen = new Set<string>();
  const add = (p: Pkg) => {
    const key = `${p.name}\n${p.version}\n${p.purl ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    if (out.length >= MAX_PACKAGES) throw new SbomError(`An image may list at most ${MAX_PACKAGES} packages.`);
    out.push(p);
  };
  if (body.bomFormat === "CycloneDX") {
    for (const c of Array.isArray(body.components) ? body.components : []) {
      if (!isObj(c) || c.type === "operating-system" || c.type === "file") continue;
      const name = str(c.name, 256);
      if (!name) continue;
      add({ name, version: str(c.version, 128) ?? "", purl: str(c.purl, 512), licence: cdxLicence(c.licenses) });
    }
    return { format: "cyclonedx-json", packages: out };
  }
  if (typeof body.spdxVersion === "string" && Array.isArray(body.packages)) {
    for (const p of body.packages) {
      if (!isObj(p)) continue;
      const name = str(p.name, 256);
      if (!name) continue;
      const ref = Array.isArray(p.externalRefs) ? p.externalRefs.find((r: unknown) => isObj(r) && r.referenceType === "purl") : undefined;
      add({ name, version: str(p.versionInfo, 128) ?? "", purl: str(isObj(ref) ? ref.referenceLocator : undefined, 512), licence: spdxLicence(p) });
    }
    return { format: "spdx-json", packages: out };
  }
  throw new SbomError("Send a CycloneDX JSON or SPDX JSON SBOM, for example from `syft <image> -o cyclonedx-json`.");
}
