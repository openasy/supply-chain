// What the search window (Cmd+K) finds in Supply Chain: images by name or digest, from the API.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Container } from "lucide-react";
import type { Image } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;
const query = (q: string) => new URLSearchParams({ q, limit: "8" });

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const found = await call<{ images: Image[] }>(`/api/v1/images?${query(q)}`, { signal });
    return found.images.map((i): SearchResult => ({
      id: `image:${i.id}`,
      label: i.name,
      detail: `${i.allowed ? t("search.allowed") : t("search.denied")} · ${i.digest.slice(0, 19)}`,
      kind: t("search.image"),
      icon: Container,
      severity: i.allowed ? undefined : "high",
      mono: true,
      href: `/images/${encodeURIComponent(i.id)}`,
    }));
  };
}
