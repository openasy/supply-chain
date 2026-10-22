// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createSupply } from "./supply.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

export const digest = (n: number) => `sha256:${n.toString(16).padStart(64, "0")}`;

/** A CycloneDX SBOM as Syft writes it, with these packages: name, version, licence expression. */
export function cyclonedx(...packages: Array<[string, string, string?]>) {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    components: [
      { type: "operating-system", name: "debian", version: "12" },
      ...packages.map(([name, version, licence]) => ({
        type: "library",
        name,
        version,
        purl: `pkg:deb/debian/${name}@${version}`,
        ...(licence && { licenses: [{ expression: licence }] }),
      })),
    ],
  };
}

export const spdx = (...packages: Array<[string, string, string?]>) => ({
  spdxVersion: "SPDX-2.3",
  packages: packages.map(([name, version, licence]) => ({
    name,
    versionInfo: version,
    licenseConcluded: licence ?? "NOASSERTION",
    licenseDeclared: "NOASSERTION",
    externalRefs: [{ referenceType: "purl", referenceLocator: `pkg:deb/debian/${name}@${version}` }],
  })),
});

export const signed = { verified: true, identity: "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1", issuer: "https://token.actions.githubusercontent.com" };
export const slsa = (level: number) => ({ builder: "https://github.com/slsa-framework/slsa-github-generator", sourceRepo: "github.com/acme/app", sourceCommit: "abc123", level });

export async function startApp(opts: Partial<AppOptions> & { version: string }) {
  const db = openDb(":memory:");
  const supply = createSupply(db);
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "supply-chain", productName: "OpenAsy Supply Chain", origin: base });
  handler = createApp({ db, supply, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...opts });
  const as = (token: string) => (path: string, init: RequestInit = {}) => fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  /** Sends evidence the way CI does. */
  const send = (name: string, dig: string, evidence: unknown) => ingest(`/api/v1/images?${new URLSearchParams({ name, digest: dig })}`, { method: "POST", body: JSON.stringify(evidence) });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, supply, auth, base, admin, ingest, send, close };
}
