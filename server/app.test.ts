import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { cyclonedx, digest, signed, slsa, spdx, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const json = async (res: Response) => (await res.json()) as any;
const APP = "ghcr.io/acme/app";
const sbom = cyclonedx(["openssl", "3.0.11", "Apache-2.0"], ["zlib", "1.2.13", "Zlib"], ["bash", "5.2", "GPL-3.0-or-later"]);
const check = async (name: string, dig: string) => json(await app.ingest(`/api/v1/images/check?${new URLSearchParams({ name, digest: dig })}`));
const putPolicy = (changes: Record<string, unknown>, base?: Record<string, unknown>) =>
  app.admin("/api/v1/policy", { method: "PUT", body: JSON.stringify({ ...(base ?? DEFAULT), ...changes }) });
const DEFAULT = {
  requireSignature: true,
  allowedIdentities: [],
  allowedIssuers: [],
  requireSbom: true,
  requireProvenance: false,
  minProvenanceLevel: 0,
  licenceAllow: [],
  licenceDeny: [],
};
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("evidence and the admission answer", () => {
  it("denies an image nobody reported on", async () => {
    expect(await check(APP, digest(1))).toEqual({
      allowed: false,
      image: null,
      reasons: [{ rule: "unknown-image", message: expect.stringContaining("CI must report it first"), waived: false }],
    });
  });

  it("allows an image with a signature and an SBOM under the default policy", async () => {
    const res = await app.send(APP, digest(1), { sbom, signature: signed, provenance: slsa(3) });
    expect(res.status).toBe(201);
    const image = await json(res);
    expect(image).toMatchObject({
      name: APP,
      digest: digest(1),
      allowed: true,
      reasons: [],
      sbom: { format: "cyclonedx-json", packages: 3 },
      signature: { verified: true, identity: signed.identity },
      provenance: { level: 3, sourceCommit: "abc123" },
    });
    expect(await check(APP, digest(1))).toMatchObject({ allowed: true, reasons: [], image: { id: image.id } });
  });

  it("adds evidence to what is there, and tells a new image from an old one", async () => {
    const res = await app.send(APP, digest(2), { provenance: slsa(1) });
    expect(res.status).toBe(201);
    expect(await json(res)).toMatchObject({ allowed: false, sbom: null, signature: null, provenance: { level: 1 } });
    expect((await check(APP, digest(2))).reasons.map((r: { rule: string }) => r.rule).sort()).toEqual(["sbom", "signature"]);
    const more = await app.send(APP, digest(2), { sbom: spdx(["curl", "8.4.0", "MIT"]), signature: signed });
    expect(more.status).toBe(200);
    expect(await json(more)).toMatchObject({ allowed: true, sbom: { format: "spdx-json", packages: 1 }, provenance: { level: 1 } });
  });

  it("replaces an SBOM and its packages when a new one comes", async () => {
    await app.send(APP, digest(3), { sbom: cyclonedx(["a", "1"], ["b", "1"]), signature: signed });
    await app.send(APP, digest(3), { sbom: cyclonedx(["c", "1"]) });
    const id = (await check(APP, digest(3))).image.id;
    expect((await json(await app.admin(`/api/v1/images/${id}/packages`))).packages.map((p: { name: string }) => p.name)).toEqual(["c"]);
  });

  it("takes a gzipped body", async () => {
    const res = await app.ingest(`/api/v1/images?${new URLSearchParams({ name: "ghcr.io/acme/zipped", digest: digest(9) })}`, {
      method: "POST",
      body: gzipSync(JSON.stringify({ sbom })),
      headers: { "content-encoding": "gzip" },
    });
    expect(res.status).toBe(201);
  });

  it("serves the SBOM it was given", async () => {
    const id = (await check(APP, digest(1))).image.id;
    const res = await app.admin(`/api/v1/images/${id}/sbom`);
    expect(res.headers.get("x-sbom-format")).toBe("cyclonedx-json");
    expect(await json(res)).toMatchObject({ bomFormat: "CycloneDX" });
    const none = await json(await app.send(APP, digest(4), { signature: signed }));
    expect((await app.admin(`/api/v1/images/${none.id}/sbom`)).status).toBe(404);
  });

  it("refuses what it cannot place", async () => {
    const problem = async (res: Response, status: number, code: string) => (expect(res.status).toBe(status), expect(await json(res)).toMatchObject({ code }));
    const post = (query: Record<string, string>, body: string) => app.ingest(`/api/v1/images?${new URLSearchParams(query)}`, { method: "POST", body });
    const ok = { name: APP, digest: digest(5) };
    await problem(await post({ digest: digest(5) }, "{}"), 422, "invalid-body");
    await problem(await post({ name: "Has Spaces", digest: digest(5) }, "{}"), 422, "invalid-body");
    await problem(await post({ name: `${APP}@sha256:x`, digest: digest(5) }, "{}"), 422, "invalid-body");
    await problem(await post({ name: APP, digest: "sha256:short" }, "{}"), 422, "invalid-body");
    await problem(await post({ name: APP, digest: "latest" }, "{}"), 422, "invalid-body");
    await problem(await post(ok, "{nope"), 422, "invalid-json");
    await problem(await post(ok, "[]"), 422, "invalid-json");
    await problem(await post(ok, "{}"), 422, "invalid-body");
    await problem(await post(ok, JSON.stringify({ sbom, extra: 1 })), 422, "invalid-body");
    await problem(await post(ok, JSON.stringify({ sbom: { hello: 1 } })), 422, "invalid-sbom");
    await problem(await post(ok, JSON.stringify({ signature: { verified: "yes" } })), 422, "invalid-body");
    await problem(await post(ok, JSON.stringify({ signature: null })), 422, "invalid-body");
    await problem(await post(ok, JSON.stringify({ provenance: { level: 9 } })), 422, "invalid-body");
    await problem(await post(ok, JSON.stringify({ provenance: { builder: "x" } })), 422, "invalid-body");
    await problem(await app.ingest(`/api/v1/images/check?name=${APP}&digest=bad`), 422, "invalid-body");
    await problem(await app.ingest(`/api/v1/images/check?digest=${digest(1)}`), 422, "invalid-body");
  });
});

describe("the policy", () => {
  it("starts strict about signatures and SBOMs and says so", async () => {
    expect(await json(await app.admin("/api/v1/policy"))).toEqual(DEFAULT);
  });

  it("denies a signature that did not verify, and one that was never checked", async () => {
    await app.send("ghcr.io/acme/bad", digest(10), { sbom, signature: { verified: false } });
    expect(await check("ghcr.io/acme/bad", digest(10))).toMatchObject({
      allowed: false,
      reasons: [{ rule: "signature", message: "The signature did not verify." }],
    });
    await app.send("ghcr.io/acme/unchecked", digest(11), { sbom });
    expect((await check("ghcr.io/acme/unchecked", digest(11))).reasons[0].message).toContain("No signature check");
  });

  it("can do without signatures and SBOMs", async () => {
    await putPolicy({ requireSignature: false, requireSbom: false });
    expect(await check("ghcr.io/acme/unchecked", digest(11))).toMatchObject({ allowed: true });
    expect(await check("ghcr.io/acme/bad", digest(10))).toMatchObject({ allowed: true });
    await putPolicy({});
  });

  it("holds the signer to allowed identities (regular expressions) and issuers", async () => {
    await putPolicy({ allowedIdentities: ["^https://github\\.com/acme/.+/\\.github/workflows/release\\.yml@refs/tags/v.+$"] });
    expect(await check(APP, digest(1))).toMatchObject({ allowed: true });
    await app.send("ghcr.io/acme/other", digest(12), {
      sbom,
      signature: { verified: true, identity: "https://github.com/evil/app/.github/workflows/release.yml@refs/tags/v1", issuer: signed.issuer },
    });
    expect(await check("ghcr.io/acme/other", digest(12))).toMatchObject({
      allowed: false,
      reasons: [{ rule: "signature", message: expect.stringContaining("does not allow") }],
    });
    await putPolicy({ allowedIdentities: [], allowedIssuers: ["https://accounts.google.com"] });
    expect(await check(APP, digest(1))).toMatchObject({ allowed: false, reasons: [{ rule: "signature", message: expect.stringContaining("issuer") }] });
    await putPolicy({});
  });

  it("holds provenance to a SLSA level", async () => {
    await putPolicy({ minProvenanceLevel: 2 });
    expect(await check(APP, digest(1))).toMatchObject({ allowed: true });
    expect(await check(APP, digest(2))).toMatchObject({
      allowed: false,
      reasons: [{ rule: "provenance", message: expect.stringContaining("level 1; the policy needs 2") }],
    });
    expect(await check(APP, digest(3))).toMatchObject({ allowed: false, reasons: [{ rule: "provenance", message: expect.stringContaining("No provenance") }] });
    await putPolicy({ minProvenanceLevel: 0, requireProvenance: true });
    expect(await check(APP, digest(2))).toMatchObject({ allowed: true });
    expect(await check(APP, digest(3))).toMatchObject({ allowed: false });
    await putPolicy({});
  });

  it("denies licences by list, and an OR is fine when one alternative is", async () => {
    await app.send("ghcr.io/acme/dual", digest(13), { sbom: cyclonedx(["x", "1", "GPL-3.0-only OR MIT"]), signature: signed });
    await putPolicy({ licenceDeny: ["GPL-3.0-or-later", "GPL-3.0-only"] });
    expect(await check(APP, digest(1))).toMatchObject({
      allowed: false,
      reasons: [{ rule: "licences", message: expect.stringContaining("1 packages carry licences") }],
    });
    expect(await check("ghcr.io/acme/dual", digest(13))).toMatchObject({ allowed: true });
    await putPolicy({ licenceAllow: ["MIT"], licenceDeny: [] });
    expect(await check("ghcr.io/acme/dual", digest(13))).toMatchObject({ allowed: true });
    // An allow list also refuses packages whose licence nobody named.
    await app.send("ghcr.io/acme/unnamed", digest(14), { sbom: cyclonedx(["y", "1"]), signature: signed });
    expect(await check("ghcr.io/acme/unnamed", digest(14))).toMatchObject({ allowed: false, reasons: [{ rule: "licences" }] });
    const detail = await json(await app.admin(`/api/v1/images/${(await check(APP, digest(1))).image.id}`));
    expect(detail.licences).toEqual(
      expect.arrayContaining([
        { licence: "GPL-3.0-or-later", packages: 1, verdict: "denied" },
        { licence: "Zlib", packages: 1, verdict: "denied" },
      ]),
    );
    await putPolicy({});
  });

  it("refuses a policy it cannot read, and a typo that would loosen it", async () => {
    for (const bad of [
      { requireSignature: "yes" },
      { minProvenanceLevel: 5 },
      { minProvenanceLevel: 1.5 },
      { allowedIdentities: ["("] },
      { allowedIdentities: "x" },
      { licenceAllow: [""] },
      { requireSignatur: false },
      { licenceDeny: Array.from({ length: 201 }, () => "x") },
    ]) {
      expect((await putPolicy(bad)).status, JSON.stringify(bad)).toBe(422);
    }
    const missing = { ...DEFAULT } as Record<string, unknown>;
    delete missing.requireSbom;
    expect((await putPolicy({}, missing)).status).toBe(422);
    expect(await json(await app.admin("/api/v1/policy"))).toEqual(DEFAULT);
  });
});

describe("exceptions", () => {
  const add = (body: Record<string, unknown>) => app.admin("/api/v1/exceptions", { method: "POST", body: JSON.stringify(body) });

  it("waives one rule for one image name, with a reason and an end", async () => {
    await putPolicy({ licenceDeny: ["GPL-3.0-or-later"] });
    expect((await check(APP, digest(1))).allowed).toBe(false);
    const before = await json(await app.admin("/api/v1/summary"));
    expect(before.deniedBy.licences).toBeGreaterThanOrEqual(1);
    expect(before.licences).toContainEqual(expect.objectContaining({ licence: "GPL-3.0-or-later", verdict: "denied" }));
    const made = await json(await add({ name: APP, rule: "licences", reason: "bash is only used in the build stage", expiresAt: inDays(30) }));
    expect(made).toMatchObject({ name: APP, digest: null, rule: "licences", by: "admin token", active: true });
    expect(await check(APP, digest(1))).toMatchObject({ allowed: true, reasons: [{ rule: "licences", waived: true }] });
    const after = await json(await app.admin("/api/v1/summary"));
    expect(after.allowedByException).toBe(1);
    // What an exception waives no longer counts as a denial.
    expect(after.deniedBy.licences).toBeLessThan(before.deniedBy.licences);
    expect((await json(await app.admin("/api/v1/images?state=allowed&q=acme/app"))).images.length).toBeGreaterThan(1);
    // Another rule is still enforced.
    await app.send(APP, digest(15), { sbom, signature: { verified: false } });
    expect((await check(APP, digest(15))).allowed).toBe(false);
    expect((await app.admin(`/api/v1/exceptions/${made.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await check(APP, digest(1))).allowed).toBe(false);
    expect((await app.admin(`/api/v1/exceptions/${made.id}`, { method: "DELETE" })).status).toBe(404);
  });

  it("can be tied to one digest, or cover every rule", async () => {
    await add({ name: APP, digest: digest(1), rule: "licences", reason: "Reviewed this build", expiresAt: inDays(7) });
    expect((await check(APP, digest(1))).allowed).toBe(true);
    expect((await check(APP, digest(2))).allowed).toBe(true);
    await app.send(APP, digest(16), { sbom, signature: { verified: false } });
    expect((await check(APP, digest(16))).allowed).toBe(false);
    await add({ name: APP, rule: "all", reason: "Migration freeze", expiresAt: inDays(3) });
    expect((await check(APP, digest(16))).allowed).toBe(true);
  });

  it("stops applying when it ends", async () => {
    app.db.prepare("UPDATE exceptions SET expires_at = ?").run(new Date(Date.now() - 1000).toISOString());
    expect((await check(APP, digest(1))).allowed).toBe(false);
    const list = (await json(await app.admin("/api/v1/exceptions"))).exceptions;
    expect(list.every((e: { active: boolean }) => !e.active)).toBe(true);
    await putPolicy({});
  });

  it("needs a reason, a known rule and an end within a year", async () => {
    const ok = { name: APP, rule: "licences", reason: "Fine for now", expiresAt: inDays(10) };
    for (const bad of [
      { reason: "" },
      { reason: "x".repeat(501) },
      { rule: "everything" },
      { expiresAt: inDays(-1) },
      { expiresAt: inDays(400) },
      { expiresAt: "soon" },
      { name: "Bad Name" },
      { digest: "latest" },
      { extra: 1 },
    ]) {
      expect((await add({ ...ok, ...bad })).status, JSON.stringify(bad)).toBe(422);
    }
  });
});

describe("the SBOM store", () => {
  it("tells which images contain a package, at any version or one", async () => {
    await app.send("ghcr.io/acme/old", digest(20), { sbom: cyclonedx(["openssl", "1.1.1w", "OpenSSL"]), signature: signed });
    const all = (await json(await app.admin("/api/v1/packages?name=openssl"))).usages;
    expect(all.map((u: { image: { name: string }; version: string }) => `${u.image.name} ${u.version}`)).toEqual(
      expect.arrayContaining([`${APP} 3.0.11`, "ghcr.io/acme/old 1.1.1w"]),
    );
    const one = (await json(await app.admin("/api/v1/packages?name=openssl&version=1.1.1w"))).usages;
    expect(one).toEqual([
      {
        image: { id: expect.any(String), name: "ghcr.io/acme/old", digest: digest(20) },
        package: "openssl",
        version: "1.1.1w",
        purl: "pkg:deb/debian/openssl@1.1.1w",
        licence: "OpenSSL",
      },
    ]);
    expect((await json(await app.admin("/api/v1/packages?name=nothing"))).usages).toEqual([]);
    expect((await app.admin("/api/v1/packages")).status).toBe(422);
  });

  it("lists and pages images, and filters by state and text", async () => {
    const first = await json(await app.admin("/api/v1/images?limit=2"));
    expect(first.images).toHaveLength(2);
    expect(first.nextCursor).toBeDefined();
    const next = await json(await app.admin(`/api/v1/images?limit=2&cursor=${first.nextCursor}`));
    expect(next.images.length).toBeGreaterThan(0);
    expect(next.images[0].id).not.toBe(first.images[0].id);
    const denied = (await json(await app.admin("/api/v1/images?state=denied&limit=500"))).images;
    expect(denied.length).toBeGreaterThan(0);
    expect(denied.every((i: { allowed: boolean }) => !i.allowed)).toBe(true);
    expect((await json(await app.admin("/api/v1/images?q=zipped"))).images.map((i: { name: string }) => i.name)).toEqual(["ghcr.io/acme/zipped"]);
    expect((await app.admin("/api/v1/images?state=maybe")).status).toBe(422);
    expect((await app.admin("/api/v1/images?q=" + "x".repeat(129))).status).toBe(422);
    expect((await app.admin("/api/v1/images?cursor=junk")).status).toBe(422);
  });

  it("pages and searches the packages of an image", async () => {
    const id = (await check(APP, digest(1))).image.id;
    expect((await json(await app.admin(`/api/v1/images/${id}/packages?limit=2`))).nextCursor).toBeDefined();
    expect((await json(await app.admin(`/api/v1/images/${id}/packages?q=ssl`))).packages.map((p: { name: string }) => p.name)).toEqual(["openssl"]);
    expect((await app.admin("/api/v1/images/missing/packages")).status).toBe(404);
  });

  it("deletes an image with its packages", async () => {
    const id = (await check("ghcr.io/acme/old", digest(20))).image.id;
    expect((await app.admin(`/api/v1/images/${id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/images/${id}`)).status).toBe(404);
    expect((await json(await app.admin("/api/v1/packages?name=openssl&version=1.1.1w"))).usages).toEqual([]);
  });
});

describe("access", () => {
  it("lets the ingest token send evidence and ask for answers, and nothing else", async () => {
    const anon = (path: string, init: RequestInit = {}) => fetch(app.base + path, init);
    expect((await anon(`/api/v1/images?name=${APP}&digest=${digest(1)}`, { method: "POST", body: "{}" })).status).toBe(401);
    expect((await anon(`/api/v1/images/check?name=${APP}&digest=${digest(1)}`)).status).toBe(401);
    expect((await anon("/api/v1/images/check?name=a&digest=b", { headers: { authorization: "Bearer nope" } })).status).toBe(401);
    expect((await app.ingest(`/api/v1/images/check?name=${APP}&digest=${digest(1)}`)).status).toBe(200);
    for (const path of ["/api/v1/images", "/api/v1/policy", "/api/v1/exceptions", "/api/v1/summary", "/api/v1/packages?name=a"])
      expect((await app.ingest(path)).status, path).toBe(401);
    expect((await app.ingest("/api/v1/policy", { method: "PUT", body: JSON.stringify(DEFAULT) })).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/images?name=a&digest=b`, { method: "POST", body: "{}" })).status).toBe(503);
    await closed.close();
  });

  it("answers version, health and metrics", async () => {
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "supply-chain", version: "0.1.0" });
    expect((await fetch(`${app.base}/healthz`)).status).toBe(200);
    expect((await fetch(`${app.base}/readyz`)).status).toBe(200);
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="supply-chain",version="0.1.0"} 1');
    expect(metrics).toMatch(/openasy_supply_chain_images \d+/);
    expect(metrics).toMatch(/openasy_supply_chain_images_denied \d+/);
  });
});
