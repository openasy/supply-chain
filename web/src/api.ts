// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Rule = "signature" | "sbom" | "provenance" | "licences";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Reason {
  rule: Rule | "unknown-image";
  message: string;
  waived: boolean;
}

export interface Image {
  id: string;
  name: string;
  digest: string;
  allowed: boolean;
  reasons: Reason[];
  sbom: { format: "cyclonedx-json" | "spdx-json"; at: string; packages: number } | null;
  signature: { verified: boolean; identity: string | null; issuer: string | null; at: string } | null;
  provenance: { builder: string | null; sourceRepo: string | null; sourceCommit: string | null; level: number | null; at: string } | null;
  createdAt: string;
  updatedAt: string;
}

export interface ImageDetail extends Image {
  licences: Array<{ licence: string; packages: number; verdict: "allowed" | "denied" | "unknown" }>;
}

export interface Package {
  name: string;
  version: string;
  purl: string | null;
  licence: string | null;
}

export interface Usage {
  image: { id: string; name: string; digest: string };
  package: string;
  version: string;
  purl: string | null;
  licence: string | null;
}

export interface Policy {
  requireSignature: boolean;
  allowedIdentities: string[];
  allowedIssuers: string[];
  requireSbom: boolean;
  requireProvenance: boolean;
  minProvenanceLevel: number;
  licenceAllow: string[];
  licenceDeny: string[];
}

export interface Exception {
  id: string;
  name: string;
  digest: string | null;
  rule: Rule | "all";
  reason: string;
  by: string | null;
  createdAt: string;
  expiresAt: string;
  active: boolean;
}

export interface Summary {
  images: number;
  allowed: number;
  denied: number;
  allowedByException: number;
  withoutSbom: number;
  activeExceptions: number;
  packages: number;
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
