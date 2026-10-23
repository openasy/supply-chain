import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, INGEST_TOKEN, cyclonedx, digest, signed, slsa, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "supply-chain-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const ingest = () => auth(INGEST_TOKEN);
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // supply-chain's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  const NAME = "ghcr.io/acme/app";
  let id = "";
  let exception = "";
  const evidence = (extra: object = {}) =>
    JSON.stringify({
      sbom: cyclonedx(["openssl", "3.0.11", "Apache-2.0"], ["bash", "5.2", "GPL-3.0-or-later"]),
      signature: signed,
      provenance: slsa(3),
      ...extra,
    });
  const send = (body = evidence(), token = INGEST_TOKEN) => auth(token, body);
  const path = (n: number, name = NAME) => `/api/v1/images?name=${name}&digest=${digest(n)}`;
  const policy = {
    requireSignature: true,
    allowedIdentities: [],
    allowedIssuers: [],
    requireSbom: true,
    requireProvenance: false,
    minProvenanceLevel: 0,
    licenceAllow: [],
    licenceDeny: [],
  };

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("evidence and every refusal", async () => {
    id = ((await call("POST", "/api/v1/images", send(), path(1))).body as { id: string }).id;
    await call("POST", "/api/v1/images", send(JSON.stringify({ provenance: slsa(2) })), path(1));
    await call("POST", "/api/v1/images", send(evidence({ signature: { verified: false } })), path(2));
    await call("POST", "/api/v1/images", send("{nope"), path(3));
    await call("POST", "/api/v1/images", send(JSON.stringify({})), path(3));
    await call("POST", "/api/v1/images", send(JSON.stringify({ sbom: { hello: 1 } })), path(3));
    await call("POST", "/api/v1/images", send(), "/api/v1/images?name=Bad Name&digest=nope");
    await call("POST", "/api/v1/images", auth("wrong", evidence()), path(4));
    await call("POST", "/api/v1/images", { method: "POST" }, path(4));
  });

  it("the admission answer", async () => {
    const q = (n: number, name = NAME) => `/api/v1/images/check?name=${name}&digest=${digest(n)}`;
    expect(((await call("GET", "/api/v1/images/check", ingest(), q(1))).body as { allowed: boolean }).allowed).toBe(true);
    await call("GET", "/api/v1/images/check", admin(), q(2));
    await call("GET", "/api/v1/images/check", admin(), q(99));
    await call("GET", "/api/v1/images/check", admin(), "/api/v1/images/check?name=x");
    await call("GET", "/api/v1/images/check", auth("wrong"), q(1));
    await call("GET", "/api/v1/images/check", {}, q(1));
  });

  it("images and packages", async () => {
    await call("GET", "/api/v1/images", admin());
    await call("GET", "/api/v1/images", admin(), "/api/v1/images?state=denied&q=acme&limit=1");
    await call("GET", "/api/v1/images", admin(), "/api/v1/images?state=maybe");
    await call("GET", "/api/v1/images", {});
    await call("GET", "/api/v1/images/{id}", admin(), `/api/v1/images/${id}`);
    await call("GET", "/api/v1/images/{id}", admin(), "/api/v1/images/missing");
    await call("GET", "/api/v1/images/{id}", {}, `/api/v1/images/${id}`);
    await call("GET", "/api/v1/images/{id}/packages", admin(), `/api/v1/images/${id}/packages`);
    await call("GET", "/api/v1/images/{id}/packages", admin(), `/api/v1/images/${id}/packages?q=ssl&limit=1`);
    await call("GET", "/api/v1/images/{id}/packages", admin(), "/api/v1/images/missing/packages");
    await call("GET", "/api/v1/images/{id}/sbom", admin(), `/api/v1/images/${id}/sbom`);
    await call("GET", "/api/v1/images/{id}/sbom", admin(), "/api/v1/images/missing/sbom");
    await call("GET", "/api/v1/packages", admin(), "/api/v1/packages?name=openssl&version=3.0.11");
    await call("GET", "/api/v1/packages", admin(), "/api/v1/packages");
    await call("GET", "/api/v1/packages", {}, "/api/v1/packages?name=openssl");
  });

  it("policy", async () => {
    await call("GET", "/api/v1/policy", admin());
    await call("GET", "/api/v1/policy", {});
    await call("PUT", "/api/v1/policy", admin({ ...policy, licenceDeny: ["GPL-3.0-or-later"] }));
    await call("PUT", "/api/v1/policy", admin({ ...policy, minProvenanceLevel: 7 }));
    await call("PUT", "/api/v1/policy", admin("nope"));
    await call("PUT", "/api/v1/policy", { method: "PUT" });
    await call("GET", "/api/v1/images/{id}", admin(), `/api/v1/images/${id}`);
  });

  it("exceptions", async () => {
    exception = (
      (await call("POST", "/api/v1/exceptions", admin({ name: NAME, rule: "licences", reason: "Build stage only", expiresAt: inDays(30) }))).body as {
        id: string;
      }
    ).id;
    await call("POST", "/api/v1/exceptions", admin({ name: NAME, digest: digest(1), rule: "all", reason: "Reviewed", expiresAt: inDays(5) }));
    await call("POST", "/api/v1/exceptions", admin({ name: NAME, rule: "licences", reason: "", expiresAt: inDays(30) }));
    await call("POST", "/api/v1/exceptions", admin("nope"));
    await call("POST", "/api/v1/exceptions", {});
    await call("GET", "/api/v1/exceptions", admin());
    await call("GET", "/api/v1/exceptions", {});
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
    await call("DELETE", "/api/v1/exceptions/{id}", admin(), `/api/v1/exceptions/${exception}`);
    await call("DELETE", "/api/v1/exceptions/{id}", admin(), `/api/v1/exceptions/${exception}`);
    await call("DELETE", "/api/v1/exceptions/{id}", { method: "DELETE" }, "/api/v1/exceptions/x");
  });

  it("deletes an image", async () => {
    await call("DELETE", "/api/v1/images/{id}", admin(), `/api/v1/images/${id}`);
    await call("DELETE", "/api/v1/images/{id}", admin(), `/api/v1/images/${id}`);
    await call("DELETE", "/api/v1/images/{id}", { method: "DELETE" }, "/api/v1/images/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
