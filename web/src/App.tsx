import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  DataTable,
  Dialog,
  EmptyState,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SegmentedControl,
  SelectField,
  StatusBadge,
  Switch,
  TextField,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Download, Images, KeyRound, LogIn, LogOut, PackageSearch, ScrollText, Settings2, ShieldOff, Trash2, UserRound, Users } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, MfaSetupRequired, Unauthorized, type Exception, type Image, type ImageDetail, type Package, type Policy, type ProductLink, type Summary, type Usage } from "./api.ts";

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const PAGES = ["packages", "policy", "exceptions", "setup", "account", "members", "signin", "tokens"] as const;
type Route = { page: "images" | (typeof PAGES)[number] } | { page: "image"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["images", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "images" && id) return { page: "image", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "images" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;


function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

const short = (digest: string) => digest.replace("sha256:", "").slice(0, 12);

function StateBadge({ image }: { image: Pick<Image, "allowed" | "reasons"> }) {
  if (!image.allowed) return <StatusBadge tone="danger">Denied</StatusBadge>;
  return image.reasons.length ? <StatusBadge tone="warning">Allowed by exception</StatusBadge> : <StatusBadge tone="success">Allowed</StatusBadge>;
}

const RULE_LABEL: Record<string, string> = { signature: "Signature", sbom: "SBOM", provenance: "Provenance", licences: "Licences", "unknown-image": "Unknown image", all: "Every rule" };

function ImagesPage({ call, summary }: { call: Call; summary?: Summary }) {
  const [state, setState] = useState<"all" | "allowed" | "denied">("all");
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<Image[]>();
  const [more, setMore] = useState<string>();

  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ limit: "100" });
      if (state !== "all") p.set("state", state);
      if (q.trim()) p.set("q", q.trim());
      if (cursor) p.set("cursor", cursor);
      return call<{ images: Image[]; nextCursor?: string }>(`/api/v1/images?${p}`);
    },
    [call, state, q],
  );
  useEffect(() => void query().then((r) => (setRows(r.images), setMore(r.nextCursor)), () => setRows([])), [query]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.images]), setMore(r.nextCursor)));

  const columns: Column<Image>[] = [
    { id: "state", header: "State", width: "170px", cell: (i) => <StateBadge image={i} /> },
    {
      id: "name",
      header: "Image",
      width: "36%",
      sortValue: (i) => i.name,
      cell: (i) => (
        <span className="flex min-w-0 flex-col">
          <a href={`/images/${i.id}`} className="supply-wrap font-medium">
            {i.name}
          </a>
          <span className="font-mono text-xs text-fg-muted">{short(i.digest)}</span>
        </span>
      ),
    },
    {
      id: "why",
      header: "What the policy has against it",
      cell: (i) =>
        i.reasons.length ? (
          <span className="flex flex-wrap gap-1">
            {i.reasons.map((r) => (
              <Badge key={r.message} tone={r.waived ? "neutral" : "danger"}>
                {RULE_LABEL[r.rule]}
                {r.waived ? " (waived)" : ""}
              </Badge>
            ))}
          </span>
        ) : (
          <span className="text-xs text-fg-muted">Nothing</span>
        ),
    },
    { id: "evidence", header: "Evidence", cell: (i) => <span className="text-xs whitespace-nowrap">{[i.sbom && "SBOM", i.signature && (i.signature.verified ? "signed" : "unsigned"), i.provenance && `SLSA ${i.provenance.level ?? 0}`].filter(Boolean).join(" · ") || "none"}</span> },
    { id: "updated", header: "Updated", sortValue: (i) => i.updatedAt, cell: (i) => <span className="text-xs whitespace-nowrap">{ago(i.updatedAt)}</span> },
  ];
  return (
    <>
      <PageHeader title="Images" description={summary ? `${plural(summary.images, "image")} · ${summary.packages.toLocaleString()} packages in their SBOMs` : undefined} actions={<SearchInput label="Search name or digest" className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />} />
      {summary && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Allowed" value={summary.allowed} tone="success" />
          <KpiCard label="Denied" value={summary.denied} tone={summary.denied ? "danger" : "success"} />
          <KpiCard label="Allowed by exception" value={summary.allowedByException} tone={summary.allowedByException ? "warning" : "success"} />
          <KpiCard label="Without SBOM" value={summary.withoutSbom} tone={summary.withoutSbom ? "warning" : "success"} />
        </KpiGrid>
      )}
      <FilterBar onClear={() => (setState("all"), setQ(""))}>
        <SegmentedControl
          label="State"
          size="sm"
          value={state}
          onChange={setState}
          options={[
            { value: "all", label: "All" },
            { value: "allowed", label: "Allowed" },
            { value: "denied", label: "Denied" },
          ]}
        />
      </FilterBar>
      <Panel
        title="Images"
        description="Judged by the policy of the moment. Ask the same question from a webhook with GET /api/v1/images/check."
        flush
        footer={
          more ? (
            <Button size="sm" onClick={loadMore}>
              Load more
            </Button>
          ) : undefined
        }
      >
        <DataTable label="Images" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(i) => i.id} minWidth={900} pageSize={50} empty={<EmptyState title="No images">Nothing matches these filters.</EmptyState>} />
      </Panel>
    </>
  );
}

function ExceptionDialog({ call, image, rule, open, onClose, onDone }: { call: Call; image: Image; rule: string; open: boolean; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("30");
  const [scope, setScope] = useState("name");
  const [error, setError] = useState<string>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/exceptions", { method: "POST", body: JSON.stringify({ name: image.name, ...(scope === "digest" && { digest: image.digest }), rule, reason, expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }) });
      setReason("");
      setError(undefined);
      onDone();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => !o && onClose()}
      title={`Waive ${RULE_LABEL[rule]?.toLowerCase() ?? rule} for ${image.name}`}
      description="The image is allowed again until the exception ends, and the answer says it is waived. Say why, for the next review."
      onSubmit={submit}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
            Add exception
          </Button>
        </>
      }
    >
      <TextField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} hint="Why it is acceptable, for the next review." error={error} />
      <div className="grid grid-cols-2 gap-2">
        <SelectField
          label="Applies to"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          options={[
            { value: "name", label: "Every build of this image" },
            { value: "digest", label: "This build only" },
          ]}
        />
        <SelectField
          label="For"
          value={days}
          onChange={(e) => setDays(e.target.value)}
          options={[
            { value: "7", label: "7 days" },
            { value: "30", label: "30 days" },
            { value: "90", label: "90 days" },
            { value: "365", label: "1 year" },
          ]}
        />
      </div>
    </Dialog>
  );
}

function ImagePage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const { can } = useAuth();
  const [image, setImage] = useState<ImageDetail | null>();
  const [packages, setPackages] = useState<Package[]>();
  const [q, setQ] = useState("");
  const [waiving, setWaiving] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);

  const load = useCallback(() => void call<ImageDetail>(`/api/v1/images/${id}`).then(setImage, () => setImage(null)), [call, id]);
  useEffect(load, [load]);
  useEffect(() => void call<{ packages: Package[] }>(`/api/v1/images/${id}/packages?limit=500${q.trim() ? `&q=${encodeURIComponent(q.trim())}` : ""}`).then((r) => setPackages(r.packages), () => setPackages([])), [call, id, q]);

  if (image === null)
    return (
      <EmptyState title="Image not found">
        It may have been deleted. <a href="/images">Back to images</a>.
      </EmptyState>
    );

  const columns: Column<Package>[] = [
    { id: "name", header: "Package", sortValue: (p) => p.name, cell: (p) => <span className="supply-wrap font-mono text-xs">{p.name}</span> },
    { id: "version", header: "Version", mono: true, cell: (p) => p.version || "–" },
    { id: "licence", header: "Licence", cell: (p) => <span className="supply-wrap text-xs">{p.licence ?? "not stated"}</span> },
  ];
  const verdictTone = { allowed: "success", denied: "danger", unknown: "neutral" } as const;
  return (
    <>
      <PageHeader
        title={image?.name ?? "Image"}
        description={image ? image.digest : undefined}
        actions={
          image && (
            <span className="flex items-center gap-2">
              <StateBadge image={image} />
              {image.sbom && (
                <a href={`/api/v1/images/${id}/sbom`}>
                  <Button size="sm" icon={<Download />}>
                    SBOM
                  </Button>
                </a>
              )}
            </span>
          )
        }
      />
      {image && image.reasons.length > 0 && (
        <Panel title="What the policy has against it" description={image.allowed ? "All of it is waived by an exception that has not ended." : "Fix the evidence in CI, change the policy, or waive a rule with an exception."}>
          <ul className="supply-list flex flex-col gap-2 text-sm">
            {image.reasons.map((r) => (
              <li key={r.message} className="flex flex-wrap items-center gap-2">
                <Badge tone={r.waived ? "neutral" : "danger"}>{RULE_LABEL[r.rule]}</Badge>
                <span className="min-w-0 flex-1">{r.message}</span>
                {r.waived ? (
                  <StatusBadge tone="neutral">Waived</StatusBadge>
                ) : (
                  can("editor") &&
                  r.rule !== "unknown-image" && (
                    <Button size="sm" icon={<ShieldOff />} onClick={() => setWaiving(r.rule)}>
                      Waive
                    </Button>
                  )
                )}
              </li>
            ))}
          </ul>
          {image && waiving && (
            <ExceptionDialog
              call={call}
              image={image}
              rule={waiving}
              open
              onClose={() => setWaiving(null)}
              onDone={() => {
                setWaiving(null);
                load();
                reload();
              }}
            />
          )}
        </Panel>
      )}
      {image && (
        <Panel title="Evidence" description="What CI reported. This product records it and does not verify signatures or provenance itself.">
          <dl className="m-0 grid gap-x-4 gap-y-1 text-sm" style={{ gridTemplateColumns: "auto minmax(0, 1fr)" }}>
            <dt className="text-fg-muted">SBOM</dt>
            <dd className="m-0">{image.sbom ? `${image.sbom.format}, ${plural(image.sbom.packages, "package")}, ${ago(image.sbom.at)}` : "none"}</dd>
            <dt className="text-fg-muted">Signature</dt>
            <dd className="supply-wrap m-0">{image.signature ? `${image.signature.verified ? "verified" : "did not verify"}${image.signature.identity ? ` · ${image.signature.identity}` : ""}${image.signature.issuer ? ` · ${image.signature.issuer}` : ""}` : "not reported"}</dd>
            <dt className="text-fg-muted">Provenance</dt>
            <dd className="supply-wrap m-0">{image.provenance ? `SLSA level ${image.provenance.level ?? 0}${image.provenance.sourceRepo ? ` · ${image.provenance.sourceRepo}` : ""}${image.provenance.sourceCommit ? `@${image.provenance.sourceCommit.slice(0, 8)}` : ""}${image.provenance.builder ? ` · built by ${image.provenance.builder}` : ""}` : "not reported"}</dd>
          </dl>
        </Panel>
      )}
      {image && image.licences.length > 0 && (
        <Panel title="Licences" description="Every licence in the SBOM, as the policy judges it.">
          <ul className="supply-list flex flex-wrap gap-1.5">
            {image.licences.map((l) => (
              <li key={l.licence}>
                <Badge tone={verdictTone[l.verdict]}>
                  {l.licence}: {l.packages}
                </Badge>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      <Panel title="Packages" actions={<SearchInput label="Search packages" className="w-56" value={q} onChange={(e) => setQ(e.target.value)} />} flush>
        <DataTable label="Packages" columns={columns} rows={packages ?? []} loading={!packages} getRowId={(p) => `${p.name}@${p.version}@${p.purl ?? ""}`} minWidth={640} pageSize={50} empty={<EmptyState title="No packages">{image?.sbom ? "Nothing matches." : "No SBOM has been stored for this image."}</EmptyState>} />
      </Panel>
      {can("admin") && image && (
        <Panel title="Delete" description="Removes the image with its SBOM and packages. CI reports it again on its next build.">
          <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
            Delete image
          </Button>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={`Delete ${image.name}?`}
            description="An admission check for this digest is denied until CI reports it again."
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  Cancel
                </Button>
                <Button
                  type="button"
                  variant="primary"
                  onClick={() =>
                    void call(`/api/v1/images/${id}`, { method: "DELETE" }).then(() => {
                      reload();
                      navigate("/images");
                    })
                  }
                >
                  Delete
                </Button>
              </>
            }
          >
            <></>
          </Dialog>
        </Panel>
      )}
    </>
  );
}

function PackagesPage({ call }: { call: Call }) {
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [rows, setRows] = useState<Usage[]>();
  const [searched, setSearched] = useState(false);
  const search = (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    const p = new URLSearchParams({ name: name.trim(), limit: "500" });
    if (version.trim()) p.set("version", version.trim());
    setSearched(true);
    void call<{ usages: Usage[] }>(`/api/v1/packages?${p}`).then((r) => setRows(r.usages), () => setRows([]));
  };
  const columns: Column<Usage>[] = [
    {
      id: "image",
      header: "Image",
      cell: (u) => (
        <a href={`/images/${u.image.id}`} className="supply-wrap">
          {u.image.name} <span className="font-mono text-xs text-fg-muted">{short(u.image.digest)}</span>
        </a>
      ),
    },
    { id: "version", header: "Version", mono: true, cell: (u) => u.version || "–" },
    { id: "licence", header: "Licence", cell: (u) => <span className="text-xs">{u.licence ?? "not stated"}</span> },
  ];
  return (
    <>
      <PageHeader title="Where used" description="Which images contain a package, in every stored SBOM. Use it the day a library turns out to be vulnerable." />
      <Panel>
        <form onSubmit={search} className="grid items-end gap-2 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_auto]">
          <TextField label="Package" value={name} onChange={(e) => setName(e.target.value)} hint="The name, exactly, such as openssl." />
          <TextField label="Version" value={version} onChange={(e) => setVersion(e.target.value)} hint="Optional, exactly." />
          <Button type="submit" variant="primary" disabled={!name.trim()}>
            Search
          </Button>
        </form>
      </Panel>
      {searched && (
        <Panel title="Images" flush>
          <DataTable label="Images with the package" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(u) => `${u.image.id}@${u.version}`} minWidth={640} empty={<EmptyState title="No image contains it">Nothing matches this name and version.</EmptyState>} />
        </Panel>
      )}
    </>
  );
}

const lines = (s: string) => s.split("\n").map((l) => l.trim()).filter(Boolean);

function PolicyPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [saved, setSaved] = useState<Policy>();
  const [p, setP] = useState<Policy>();
  const [identities, setIdentities] = useState("");
  const [issuers, setIssuers] = useState("");
  const [allow, setAllow] = useState("");
  const [deny, setDeny] = useState("");
  const [error, setError] = useState<string>();
  const [done, setDone] = useState(false);
  const show = (x: Policy) => (setSaved(x), setP(x), setIdentities(x.allowedIdentities.join("\n")), setIssuers(x.allowedIssuers.join("\n")), setAllow(x.licenceAllow.join("\n")), setDeny(x.licenceDeny.join("\n")));
  useEffect(() => void call<Policy>("/api/v1/policy").then(show, () => {}), [call]);

  const save = async () => {
    if (!p) return;
    try {
      show(await call<Policy>("/api/v1/policy", { method: "PUT", body: JSON.stringify({ ...p, allowedIdentities: lines(identities), allowedIssuers: lines(issuers), licenceAllow: lines(allow), licenceDeny: lines(deny) }) }));
      setError(undefined);
      setDone(true);
      reload();
    } catch (err) {
      setDone(false);
      setError((err as Error).message);
    }
  };
  const readOnly = !can("admin");
  const area = (label: string, hint: string, value: string, set: (v: string) => void) => (
    <label className="flex flex-col gap-1 text-sm">
      <span className="font-medium">{label}</span>
      <textarea className="supply-textarea" value={value} onChange={(e) => (set(e.target.value), setDone(false))} readOnly={readOnly} spellCheck={false} />
      <span className="text-xs text-fg-muted">{hint}</span>
    </label>
  );
  return (
    <>
      <PageHeader title="Policy" description="What every image must show before it may run. It applies to all images at once, and the answer to a webhook follows it the moment it changes." />
      {p && (
        <>
          <Panel title="Signature" description="CI runs cosign verify and reports the result; this product records it.">
            <div className="flex flex-col gap-3">
              <Switch checked={p.requireSignature} onCheckedChange={(v) => (setP({ ...p, requireSignature: v }), setDone(false))} label="Require a verified signature" disabled={readOnly} />
              {area("Allowed signer identities", "One regular expression per line. The signer's identity must match one. Empty: any identity.", identities, setIdentities)}
              {area("Allowed issuers", "One exact issuer per line, such as https://token.actions.githubusercontent.com. Empty: any issuer.", issuers, setIssuers)}
            </div>
          </Panel>
          <Panel title="SBOM and provenance">
            <div className="flex flex-col gap-3">
              <Switch checked={p.requireSbom} onCheckedChange={(v) => (setP({ ...p, requireSbom: v }), setDone(false))} label="Require an SBOM" disabled={readOnly} />
              <Switch checked={p.requireProvenance} onCheckedChange={(v) => (setP({ ...p, requireProvenance: v }), setDone(false))} label="Require provenance" disabled={readOnly} />
              <SelectField
                label="Lowest SLSA build level"
                value={String(p.minProvenanceLevel)}
                onChange={(e) => (setP({ ...p, minProvenanceLevel: Number(e.target.value) }), setDone(false))}
                disabled={readOnly}
                options={[0, 1, 2, 3, 4].map((n) => ({ value: String(n), label: n === 0 ? "Any" : `Level ${n}` }))}
              />
            </div>
          </Panel>
          <Panel title="Licences" description="SPDX ids. An OR expression passes when one alternative does; an AND needs every part. With an allow list, a package whose licence nobody named is denied.">
            <div className="grid gap-3 sm:grid-cols-2">
              {area("Allowed", "One id per line. Empty: any licence that is not denied.", allow, setAllow)}
              {area("Denied", "One id per line, such as AGPL-3.0-only.", deny, setDeny)}
            </div>
          </Panel>
          {can("admin") ? (
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={() => void save()} disabled={!saved}>
                Save policy
              </Button>
              {done && <StatusBadge tone="success">Saved</StatusBadge>}
              {error && <span className="text-xs text-danger">{error}</span>}
            </div>
          ) : (
            <p className="m-0 text-sm text-fg-muted">Only admins change the policy.</p>
          )}
        </>
      )}
    </>
  );
}

function ExceptionsPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<Exception[]>();
  const load = useCallback(() => void call<{ exceptions: Exception[] }>("/api/v1/exceptions").then((r) => setRows(r.exceptions), () => setRows([])), [call]);
  useEffect(load, [load]);
  const columns: Column<Exception>[] = [
    { id: "name", header: "Image", cell: (e) => <span className="supply-wrap">{e.name}{e.digest ? <span className="font-mono text-xs text-fg-muted"> {short(e.digest)}</span> : ""}</span> },
    { id: "rule", header: "Waives", cell: (e) => <Badge>{RULE_LABEL[e.rule]}</Badge> },
    { id: "reason", header: "Reason", width: "34%", cell: (e) => <span className="text-xs">{e.reason}</span> },
    { id: "by", header: "By", cell: (e) => <span className="text-xs">{e.by ?? "–"}</span> },
    { id: "expires", header: "Ends", sortValue: (e) => e.expiresAt, cell: (e) => <span className="text-xs whitespace-nowrap">{new Date(e.expiresAt).toLocaleDateString()}</span> },
    { id: "state", header: "State", cell: (e) => (e.active ? <StatusBadge tone="success">Active</StatusBadge> : <StatusBadge tone="neutral">Ended</StatusBadge>) },
    {
      id: "remove",
      header: <span className="sr-only">Remove</span>,
      label: "Remove",
      align: "right",
      cell: (e) =>
        can("editor") && (
          <IconButton label={`Remove the exception for ${e.name}`} size="sm" onClick={() => void call(`/api/v1/exceptions/${e.id}`, { method: "DELETE" }).then(() => (load(), reload()))}>
            <Trash2 />
          </IconButton>
        ),
    },
  ];
  return (
    <>
      <PageHeader title="Exceptions" description="A rule waived for an image, with a reason and an end. Add one from an image's page." />
      <Panel flush>
        <DataTable label="Exceptions" columns={columns} rows={rows ?? []} loading={!rows} getRowId={(e) => e.id} minWidth={900} empty={<EmptyState title="No exceptions">Every rule applies to every image.</EmptyState>} />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title="Setup" description="CI reports what it knows about each image it builds. The policy decides which may run, and a webhook or pipeline asks." />
      <Panel title="Report an image" description="Use SUPPLY_CHAIN_INGEST_TOKEN, set where supply-chain runs, or an API token with the editor role from API tokens.">
        <Code>{`digest=$(crane digest ghcr.io/acme/app:1.4.2)
syft ghcr.io/acme/app@$digest -o cyclonedx-json > sbom.json
cosign verify ghcr.io/acme/app@$digest \\
  --certificate-identity-regexp '^https://github.com/acme/' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null && verified=true || verified=false
jq -n --slurpfile sbom sbom.json --argjson verified $verified '{sbom: $sbom[0], signature: {verified: $verified}}' |
  curl -sf -X POST -H "Authorization: Bearer $SUPPLY_CHAIN_INGEST_TOKEN" -H 'content-type: application/json' --data-binary @- \\
  "${origin}/api/v1/images?name=ghcr.io/acme/app&digest=$digest"`}</Code>
      </Panel>
      <Panel title="Ask whether it may run" description="From an admission webhook or a pipeline. An image nobody reported on is denied.">
        <Code>{`curl -sf -H "Authorization: Bearer $SUPPLY_CHAIN_INGEST_TOKEN" \\
  "${origin}/api/v1/images/check?name=ghcr.io/acme/app&digest=$digest" | jq -e .allowed`}</Code>
      </Panel>
      <Panel title="What this product does and does not do">
        <ul className="supply-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>It records the SBOM, the signature result and the provenance summary that CI sends, and judges them against the policy.</li>
          <li>It does not verify signatures or provenance itself yet. Whoever holds the ingest token is trusted like the pipeline that runs cosign.</li>
          <li>It builds and signs nothing.</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first image arrives. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  return (
    <>
      <PageHeader title="Get started" description="Report an image from CI, then ask whether it may run." actions={<StatusBadge tone="info">Waiting for the first image</StatusBadge>} />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title="Admins only">Ask an admin of this supply-chain for access.</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: ["Members", "Who can sign in to this supply-chain, and with which role. Viewers see everything; editors also add exceptions; admins also change the policy, delete images, and manage members and tokens."],
    signin: ["Sign-in", "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role."],
    tokens: ["API tokens", "For scripts and CI. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              Sign out
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "supply-chain" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "images", label: "Images", icon: Images, count: summary?.images },
    { id: "packages", label: "Where used", icon: PackageSearch },
    { id: "policy", label: "Policy", icon: ScrollText },
    { id: "exceptions", label: "Exceptions", icon: ShieldOff, count: summary?.activeExceptions },
  ];
  const footerNav = [
    { id: "setup", label: "Setup", icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: "Members", icon: Users },
          { id: "signin", label: "Sign-in", icon: LogIn },
          { id: "tokens", label: "API tokens", icon: KeyRound },
        ]
      : []),
    { id: "account", label: "Account", icon: UserRound },
  ];
  const active = route.page === "image" ? "images" : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="supply-chain"
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "images" && summary && summary.images === 0 ? (
        <WelcomePage />
      ) : route.page === "images" ? (
        <ImagesPage call={call} summary={summary} />
      ) : route.page === "image" ? (
        <ImagePage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "packages" ? (
        <PackagesPage call={call} />
      ) : route.page === "policy" ? (
        <PolicyPage call={call} reload={reload} />
      ) : route.page === "exceptions" ? (
        <ExceptionsPage call={call} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy Supply Chain">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
