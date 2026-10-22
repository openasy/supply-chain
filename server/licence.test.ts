import { describe, expect, it } from "vitest";
import { ExpressionError, judge, normalise, parse } from "./licence.ts";

const none = { allow: [], deny: [] };
const only = (...allow: string[]) => ({ allow, deny: [] });
const deny = (...d: string[]) => ({ allow: [], deny: d });

describe("parse", () => {
  it("reads ids, groups, AND, OR and WITH", () => {
    expect(parse("MIT")).toEqual({ op: "id", id: "MIT" });
    expect(parse("MIT OR Apache-2.0")).toMatchObject({ op: "or" });
    expect(parse("GPL-2.0-only WITH Classpath-exception-2.0")).toEqual({ op: "id", id: "GPL-2.0-only" });
    // AND binds tighter than OR.
    expect(parse("A OR B AND C")).toMatchObject({ op: "or", right: { op: "and" } });
    expect(parse("(A OR B) AND C")).toMatchObject({ op: "and", left: { op: "or" } });
    expect(parse("mit or apache-2.0")).toMatchObject({ op: "or" });
  });
  it("refuses what is not an expression", () => {
    for (const bad of ["", "   ", "MIT OR", "OR MIT", "(MIT", "MIT)", "MIT AND AND BSD", "MIT WITH"]) expect(() => parse(bad), bad).toThrow(ExpressionError);
  });
});

describe("judge", () => {
  it("allows anything that is not denied when there is no allow list", () => {
    expect(judge("MIT", none)).toBe("allowed");
    expect(judge("Proprietary-Thing", none)).toBe("allowed");
  });
  it("denies what the deny list names, without case and with or without +", () => {
    expect(judge("GPL-3.0-only", deny("GPL-3.0-only"))).toBe("denied");
    expect(judge("gpl-3.0-only", deny("GPL-3.0-ONLY"))).toBe("denied");
    expect(judge("GPL-2.0+", deny("GPL-2.0"))).toBe("denied");
    expect(judge("GPL-2.0", deny("GPL-2.0+"))).toBe("denied");
    expect(judge("MIT", deny("GPL-3.0-only"))).toBe("allowed");
  });
  it("allows only what the allow list names when there is one", () => {
    expect(judge("MIT", only("MIT", "Apache-2.0"))).toBe("allowed");
    expect(judge("BSD-3-Clause", only("MIT", "Apache-2.0"))).toBe("denied");
  });
  it("accepts an OR when any alternative is allowed", () => {
    expect(judge("GPL-3.0-only OR MIT", only("MIT"))).toBe("allowed");
    expect(judge("GPL-3.0-only OR MIT", deny("GPL-3.0-only"))).toBe("allowed");
    expect(judge("GPL-3.0-only OR AGPL-3.0-only", deny("GPL-3.0-only", "AGPL-3.0-only"))).toBe("denied");
    expect(judge("GPL-3.0-only OR LGPL-3.0-only", only("MIT"))).toBe("denied");
  });
  it("needs every part of an AND", () => {
    expect(judge("MIT AND Apache-2.0", only("MIT", "Apache-2.0"))).toBe("allowed");
    expect(judge("MIT AND GPL-3.0-only", only("MIT", "Apache-2.0"))).toBe("denied");
    expect(judge("MIT AND GPL-3.0-only", deny("GPL-3.0-only"))).toBe("denied");
  });
  it("follows grouping and precedence", () => {
    // (A OR B) AND C, with A allowed, B not, C not: C fails the AND.
    expect(judge("(MIT OR GPL-3.0-only) AND BSD-3-Clause", only("MIT"))).toBe("denied");
    expect(judge("(MIT OR GPL-3.0-only) AND BSD-3-Clause", only("MIT", "BSD-3-Clause"))).toBe("allowed");
    // A OR (B AND C): A alone is enough.
    expect(judge("MIT OR GPL-3.0-only AND BSD-3-Clause", only("MIT"))).toBe("allowed");
  });
  it("judges the licence, not its exception", () => {
    expect(judge("GPL-2.0-only WITH Classpath-exception-2.0", only("GPL-2.0-only"))).toBe("allowed");
    expect(judge("GPL-2.0-only WITH Classpath-exception-2.0", deny("GPL-2.0-only"))).toBe("denied");
  });
  it("treats a licence nobody named as unknown, and as not allowed when there is an allow list", () => {
    for (const v of [null, undefined, "", "  ", "NOASSERTION", "none"]) {
      expect(judge(v, none), String(v)).toBe("unknown");
      expect(judge(v, deny("GPL-3.0-only")), String(v)).toBe("unknown");
      expect(judge(v, only("MIT")), String(v)).toBe("denied");
    }
  });
  it("compares a free-text name as one id", () => {
    expect(judge("GNU General Public License v2", deny("GNU General Public License v2"))).toBe("denied");
    expect(judge("Some Custom Terms", only("Some Custom Terms"))).toBe("allowed");
    expect(judge("Some Custom Terms", only("MIT"))).toBe("denied");
  });
});

describe("normalise", () => {
  it("drops case and a trailing +", () => {
    expect(normalise(" GPL-2.0+ ")).toBe("gpl-2.0");
  });
});
