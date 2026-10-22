import { describe, expect, it } from "vitest";
import { parseSbom, SbomError } from "./sbom.ts";
import { cyclonedx, spdx } from "./test-app.ts";

describe("parseSbom", () => {
  it("reads CycloneDX components with licences and purls, and skips the operating system", () => {
    const { format, packages } = parseSbom(cyclonedx(["openssl", "3.0.11", "Apache-2.0"], ["zlib", "1.2.13"]));
    expect(format).toBe("cyclonedx-json");
    expect(packages).toEqual([
      { name: "openssl", version: "3.0.11", purl: "pkg:deb/debian/openssl@3.0.11", licence: "Apache-2.0" },
      { name: "zlib", version: "1.2.13", purl: "pkg:deb/debian/zlib@1.2.13", licence: null },
    ]);
  });

  it("reads licence ids, names and several entries", () => {
    const sbom = {
      bomFormat: "CycloneDX",
      components: [
        { name: "a", version: "1", licenses: [{ license: { id: "MIT" } }] },
        { name: "b", version: "1", licenses: [{ license: { name: "Some Terms" } }, { license: { id: "Apache-2.0" } }] },
        { name: "c", version: "1", licenses: [{ expression: "MIT OR GPL-2.0-only" }, { license: { id: "BSD-3-Clause" } }] },
      ],
    };
    expect(parseSbom(sbom).packages.map((p) => p.licence)).toEqual(["MIT", "Some Terms AND Apache-2.0", "(MIT OR GPL-2.0-only) AND BSD-3-Clause"]);
  });

  it("reads SPDX packages, their purls and the concluded licence", () => {
    const { format, packages } = parseSbom(spdx(["curl", "8.4.0", "MIT"], ["bash", "5.2", undefined]));
    expect(format).toBe("spdx-json");
    expect(packages).toEqual([
      { name: "curl", version: "8.4.0", purl: "pkg:deb/debian/curl@8.4.0", licence: "MIT" },
      { name: "bash", version: "5.2", purl: "pkg:deb/debian/bash@5.2", licence: null },
    ]);
  });

  it("falls back to the declared licence when none was concluded", () => {
    const sbom = { spdxVersion: "SPDX-2.3", packages: [{ name: "x", versionInfo: "1", licenseConcluded: "NOASSERTION", licenseDeclared: "ISC" }] };
    expect(parseSbom(sbom).packages[0]!.licence).toBe("ISC");
  });

  it("lists a package once", () => {
    expect(parseSbom(cyclonedx(["a", "1"], ["a", "1"], ["a", "2"])).packages).toHaveLength(2);
  });

  it("refuses what is not an SBOM", () => {
    for (const bad of [[], "text", null, {}, { hello: 1 }, { bomFormat: "SPDX" }]) expect(() => parseSbom(bad), JSON.stringify(bad)).toThrow(SbomError);
  });
});
