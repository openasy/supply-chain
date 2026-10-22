// SPDX licence expressions (https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions/), as far as a policy needs
// them: ids, `+`, `WITH exception`, `AND`, `OR` and parentheses.

export type Expr = { op: "id"; id: string } | { op: "and" | "or"; left: Expr; right: Expr };

export class ExpressionError extends Error {}

/** NOASSERTION, NONE and an empty value mean nobody said which licence it is. */
export const UNKNOWN = "unknown";

/** Licence ids are compared without case, and `GPL-2.0+` is the same licence as `GPL-2.0` for a list. */
export const normalise = (id: string) => id.trim().toLowerCase().replace(/\+$/, "");

function tokens(input: string): string[] {
  const out = input.match(/\(|\)|[^\s()]+/g);
  if (!out) throw new ExpressionError("empty expression");
  return out;
}

export function parse(input: string): Expr {
  const t = tokens(input);
  let i = 0;
  const peek = () => t[i];
  const take = () => t[i++];
  const isOp = (s: string | undefined, op: string) => s?.toUpperCase() === op;

  function atom(): Expr {
    const tok = take();
    if (tok === undefined) throw new ExpressionError("expression ends too early");
    if (tok === "(") {
      const inner = or();
      if (take() !== ")") throw new ExpressionError("missing )");
      return inner;
    }
    if (tok === ")" || isOp(tok, "AND") || isOp(tok, "OR") || isOp(tok, "WITH")) throw new ExpressionError(`unexpected ${tok}`);
    // `MIT WITH Exception`: the exception does not change which licence it is.
    if (isOp(peek(), "WITH")) {
      take();
      if (take() === undefined) throw new ExpressionError("WITH needs an exception");
    }
    return { op: "id", id: tok };
  }
  function and(): Expr {
    let left = atom();
    while (isOp(peek(), "AND")) (take(), (left = { op: "and", left, right: atom() }));
    return left;
  }
  function or(): Expr {
    let left = and();
    while (isOp(peek(), "OR")) (take(), (left = { op: "or", left, right: and() }));
    return left;
  }
  const expr = or();
  if (i < t.length) throw new ExpressionError(`unexpected ${t[i]}`);
  return expr;
}

export interface LicencePolicy {
  /** Empty means any licence that is not denied. */
  allow: string[];
  deny: string[];
}

export type Verdict = "allowed" | "denied" | "unknown";

/**
 * An OR is fine if any alternative is, an AND only if every part is. A single id is denied when it is on the deny
 * list, and, when there is an allow list, also when it is not on it. A licence nobody named is `unknown`: it passes
 * without an allow list and fails with one, because the list says what may be shipped and this is not on it.
 */
export function judge(raw: string | null | undefined, policy: LicencePolicy): Verdict {
  const text = raw?.trim();
  if (!text || /^(noassertion|none)$/i.test(text)) return policy.allow.length ? "denied" : "unknown";
  let expr: Expr;
  try {
    expr = parse(text);
  } catch {
    // Not an SPDX expression (a free-text name): compared as one id, so a list can still name it.
    expr = { op: "id", id: text };
  }
  const allow = new Set(policy.allow.map(normalise));
  const deny = new Set(policy.deny.map(normalise));
  const walk = (e: Expr): boolean => {
    if (e.op === "or") return walk(e.left) || walk(e.right);
    if (e.op === "and") return walk(e.left) && walk(e.right);
    const id = normalise((e as { id: string }).id);
    if (deny.has(id)) return false;
    return allow.size === 0 || allow.has(id);
  };
  return walk(expr) ? "allowed" : "denied";
}
