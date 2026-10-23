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
  useAgo,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Download, Images, KeyRound, LogIn, LogOut, PackageSearch, ScrollText, Settings2, ShieldOff, Trash2, UserRound, Users } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type Exception,
  type Image,
  type ImageDetail,
  type Package,
  type Policy,
  type ProductLink,
  type Summary,
  type Usage,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";

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
  const t = useT();
  if (!image.allowed) return <StatusBadge tone="danger">{t("stateBadge.denied")}</StatusBadge>;
  return image.reasons.length ? (
    <StatusBadge tone="warning">{t("stateBadge.allowedByException")}</StatusBadge>
  ) : (
    <StatusBadge tone="success">{t("stateBadge.allowed")}</StatusBadge>
  );
}

const RULE_LABEL = (t: T): Record<string, string> => ({
  signature: "Signature",
  sbom: "SBOM",
  provenance: "Provenance",
  licences: "Licences",
  "unknown-image": t("ruleLabel.unknownImage"),
  all: t("ruleLabel.everyRule"),
});

function ImagesPage({ call, summary }: { call: Call; summary?: Summary }) {
  const ago = useAgo();
  const t = useT();
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
  useEffect(
    () =>
      void query().then(
        (r) => (setRows(r.images), setMore(r.nextCursor)),
        () => setRows([]),
      ),
    [query],
  );
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.images]), setMore(r.nextCursor)));

  const columns: Column<Image>[] = [
    { id: "state", header: t("imagesPage.state"), width: "170px", cell: (i) => <StateBadge image={i} /> },
    {
      id: "name",
      header: t("imagesPage.image"),
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
      header: t("imagesPage.whatThePolicyHasAgainst"),
      cell: (i) =>
        i.reasons.length ? (
          <span className="flex flex-wrap gap-1">
            {i.reasons.map((r) => (
              <Badge key={r.message} tone={r.waived ? "neutral" : "danger"}>
                {RULE_LABEL(t)[r.rule]}
                {r.waived ? " (waived)" : ""}
              </Badge>
            ))}
          </span>
        ) : (
          <span className="text-xs text-fg-muted">{t("imagesPage.nothing")}</span>
        ),
    },
    {
      id: "evidence",
      header: t("imagesPage.evidence"),
      cell: (i) => (
        <span className="text-xs whitespace-nowrap">
          {[i.sbom && "SBOM", i.signature && (i.signature.verified ? "signed" : "unsigned"), i.provenance && `SLSA ${i.provenance.level ?? 0}`]
            .filter(Boolean)
            .join(" · ") || "none"}
        </span>
      ),
    },
    {
      id: "updated",
      header: t("imagesPage.updated"),
      sortValue: (i) => i.updatedAt,
      cell: (i) => <span className="text-xs whitespace-nowrap">{ago(i.updatedAt)}</span>,
    },
  ];
  return (
    <>
      <PageHeader
        title={t("imagesPage.images")}
        description={
          summary
            ? t("imagesPage.packagesInTheirSboms", { plural: t("plurals.image", { count: summary.images }), value: summary.packages.toLocaleString() })
            : undefined
        }
        actions={<SearchInput label={t("imagesPage.searchNameOrDigest")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />}
      />
      {summary && (
        <KpiGrid minWidth={150}>
          <KpiCard label={t("imagesPage.allowed")} value={summary.allowed} tone="success" />
          <KpiCard label={t("imagesPage.denied")} value={summary.denied} tone={summary.denied ? "danger" : "success"} />
          <KpiCard label={t("imagesPage.allowedByException")} value={summary.allowedByException} tone={summary.allowedByException ? "warning" : "success"} />
          <KpiCard label={t("imagesPage.withoutSbom")} value={summary.withoutSbom} tone={summary.withoutSbom ? "warning" : "success"} />
        </KpiGrid>
      )}
      <FilterBar onClear={() => (setState("all"), setQ(""))}>
        <SegmentedControl
          label={t("imagesPage.state")}
          size="sm"
          value={state}
          onChange={setState}
          options={[
            { value: "all", label: t("imagesPage.all") },
            { value: "allowed", label: t("imagesPage.allowed") },
            { value: "denied", label: t("imagesPage.denied") },
          ]}
        />
      </FilterBar>
      <Panel
        title={t("imagesPage.images")}
        description={t("imagesPage.judgedByThePolicyOf")}
        flush
        footer={
          more ? (
            <Button size="sm" onClick={loadMore}>
              {t("imagesPage.loadMore")}
            </Button>
          ) : undefined
        }
      >
        <DataTable
          label={t("imagesPage.images")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(i) => i.id}
          minWidth={900}
          pageSize={50}
          empty={<EmptyState title={t("imagesPage.noImages")}>{t("imagesPage.nothingMatchesTheseFilters")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

function ExceptionDialog({
  call,
  image,
  rule,
  open,
  onClose,
  onDone,
}: {
  call: Call;
  image: Image;
  rule: string;
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [days, setDays] = useState("30");
  const [scope, setScope] = useState("name");
  const [error, setError] = useState<string>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/exceptions", {
        method: "POST",
        body: JSON.stringify({
          name: image.name,
          ...(scope === "digest" && { digest: image.digest }),
          rule,
          reason,
          expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString(),
        }),
      });
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
      title={t("exceptionDialog.waiveFor", { value: RULE_LABEL(t)[rule]?.toLowerCase() ?? rule, name: image.name })}
      description={t("exceptionDialog.theImageIsAllowedAgain")}
      onSubmit={submit}
      footer={
        <>
          <Button type="button" onClick={onClose}>
            {t("exceptionDialog.cancel")}
          </Button>
          <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
            {t("exceptionDialog.addException")}
          </Button>
        </>
      }
    >
      <TextField
        label={t("exceptionDialog.reason")}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        hint={t("exceptionDialog.whyItIsAcceptableFor")}
        error={error}
      />
      <div className="grid grid-cols-2 gap-2">
        <SelectField
          label={t("exceptionDialog.appliesTo")}
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          options={[
            { value: "name", label: t("exceptionDialog.everyBuildOfThisImage") },
            { value: "digest", label: t("exceptionDialog.thisBuildOnly") },
          ]}
        />
        <SelectField
          label={t("exceptionDialog.for")}
          value={days}
          onChange={(e) => setDays(e.target.value)}
          options={[
            { value: "7", label: t("exceptionDialog.n7Days") },
            { value: "30", label: t("exceptionDialog.n30Days") },
            { value: "90", label: t("exceptionDialog.n90Days") },
            { value: "365", label: t("exceptionDialog.n1Year") },
          ]}
        />
      </div>
    </Dialog>
  );
}

function ImagePage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const [image, setImage] = useState<ImageDetail | null>();
  const [packages, setPackages] = useState<Package[]>();
  const [q, setQ] = useState("");
  const [waiving, setWaiving] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);

  const load = useCallback(() => void call<ImageDetail>(`/api/v1/images/${id}`).then(setImage, () => setImage(null)), [call, id]);
  useEffect(load, [load]);
  useEffect(
    () =>
      void call<{ packages: Package[] }>(`/api/v1/images/${id}/packages?limit=500${q.trim() ? `&q=${encodeURIComponent(q.trim())}` : ""}`).then(
        (r) => setPackages(r.packages),
        () => setPackages([]),
      ),
    [call, id, q],
  );

  if (image === null)
    return (
      <EmptyState title={t("imagePage.imageNotFound")}>
        {t("imagePage.itMayHaveBeenDeleted")} <a href="/images">{t("imagePage.backToImages")}</a>.
      </EmptyState>
    );

  const columns: Column<Package>[] = [
    { id: "name", header: t("imagePage.package"), sortValue: (p) => p.name, cell: (p) => <span className="supply-wrap font-mono text-xs">{p.name}</span> },
    { id: "version", header: t("imagePage.version"), mono: true, cell: (p) => p.version || "–" },
    { id: "licence", header: t("imagePage.licence"), cell: (p) => <span className="supply-wrap text-xs">{p.licence ?? t("imagePage.notStated")}</span> },
  ];
  const verdictTone = { allowed: "success", denied: "danger", unknown: "neutral" } as const;
  return (
    <>
      <PageHeader
        title={image?.name ?? t("imagePage.image")}
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
        <Panel title={t("imagePage.whatThePolicyHasAgainst")} description={image.allowed ? t("imagePage.allOfItIsWaived") : t("imagePage.fixTheEvidenceInCi")}>
          <ul className="supply-list flex flex-col gap-2 text-sm">
            {image.reasons.map((r) => (
              <li key={r.message} className="flex flex-wrap items-center gap-2">
                <Badge tone={r.waived ? "neutral" : "danger"}>{RULE_LABEL(t)[r.rule]}</Badge>
                <span className="min-w-0 flex-1">{r.message}</span>
                {r.waived ? (
                  <StatusBadge tone="neutral">{t("imagePage.waived")}</StatusBadge>
                ) : (
                  can("editor") &&
                  r.rule !== "unknown-image" && (
                    <Button size="sm" icon={<ShieldOff />} onClick={() => setWaiving(r.rule)}>
                      {t("imagePage.waive")}
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
        <Panel title={t("imagePage.evidence")} description={t("imagePage.whatCiReportedThisProduct")}>
          <dl className="m-0 grid gap-x-4 gap-y-1 text-sm" style={{ gridTemplateColumns: "auto minmax(0, 1fr)" }}>
            <dt className="text-fg-muted">SBOM</dt>
            <dd className="m-0">
              {image.sbom ? `${image.sbom.format}, ${t("plurals.package", { count: image.sbom.packages })}, ${ago(image.sbom.at)}` : "none"}
            </dd>
            <dt className="text-fg-muted">{t("imagePage.signature")}</dt>
            <dd className="supply-wrap m-0">
              {image.signature
                ? `${image.signature.verified ? "verified" : "did not verify"}${image.signature.identity ? ` · ${image.signature.identity}` : ""}${image.signature.issuer ? ` · ${image.signature.issuer}` : ""}`
                : t("imagePage.notReported")}
            </dd>
            <dt className="text-fg-muted">{t("imagePage.provenance")}</dt>
            <dd className="supply-wrap m-0">
              {image.provenance
                ? t("imagePage.slsaLevel", {
                    value: image.provenance.level ?? 0,
                    value2: image.provenance.sourceRepo ? ` · ${image.provenance.sourceRepo}` : "",
                    value3: image.provenance.sourceCommit ? `@${image.provenance.sourceCommit.slice(0, 8)}` : "",
                    value4: image.provenance.builder ? ` · built by ${image.provenance.builder}` : "",
                  })
                : t("imagePage.notReported")}
            </dd>
          </dl>
        </Panel>
      )}
      {image && image.licences.length > 0 && (
        <Panel title={t("imagePage.licences")} description={t("imagePage.everyLicenceInTheSbom")}>
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
      <Panel
        title={t("imagePage.packages")}
        actions={<SearchInput label={t("imagePage.searchPackages")} className="w-56" value={q} onChange={(e) => setQ(e.target.value)} />}
        flush
      >
        <DataTable
          label={t("imagePage.packages")}
          columns={columns}
          rows={packages ?? []}
          loading={!packages}
          getRowId={(p) => `${p.name}@${p.version}@${p.purl ?? ""}`}
          minWidth={640}
          pageSize={50}
          empty={<EmptyState title={t("imagePage.noPackages")}>{image?.sbom ? t("imagePage.nothingMatches") : t("imagePage.noSbomHasBeenStored")}</EmptyState>}
        />
      </Panel>
      {can("admin") && image && (
        <Panel title={t("imagePage.delete")} description={t("imagePage.removesTheImageWithIts")}>
          <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
            {t("imagePage.deleteImage")}
          </Button>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={t("imagePage.delete2", { name: image.name })}
            description={t("imagePage.anAdmissionCheckForThis")}
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  {t("imagePage.cancel")}
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
                  {t("imagePage.delete")}
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
  const t = useT();
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
    void call<{ usages: Usage[] }>(`/api/v1/packages?${p}`).then(
      (r) => setRows(r.usages),
      () => setRows([]),
    );
  };
  const columns: Column<Usage>[] = [
    {
      id: "image",
      header: t("packagesPage.image"),
      cell: (u) => (
        <a href={`/images/${u.image.id}`} className="supply-wrap">
          {u.image.name} <span className="font-mono text-xs text-fg-muted">{short(u.image.digest)}</span>
        </a>
      ),
    },
    { id: "version", header: t("packagesPage.version"), mono: true, cell: (u) => u.version || "–" },
    { id: "licence", header: t("packagesPage.licence"), cell: (u) => <span className="text-xs">{u.licence ?? t("packagesPage.notStated")}</span> },
  ];
  return (
    <>
      <PageHeader title={t("packagesPage.whereUsed")} description={t("packagesPage.whichImagesContainAPackage")} />
      <Panel>
        <form onSubmit={search} className="grid items-end gap-2 sm:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_auto]">
          <TextField label={t("packagesPage.package")} value={name} onChange={(e) => setName(e.target.value)} hint={t("packagesPage.theNameExactlySuchAs")} />
          <TextField label={t("packagesPage.version")} value={version} onChange={(e) => setVersion(e.target.value)} hint={t("packagesPage.optionalExactly")} />
          <Button type="submit" variant="primary" disabled={!name.trim()}>
            {t("packagesPage.search")}
          </Button>
        </form>
      </Panel>
      {searched && (
        <Panel title={t("packagesPage.images")} flush>
          <DataTable
            label={t("packagesPage.imagesWithThePackage")}
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(u) => `${u.image.id}@${u.version}`}
            minWidth={640}
            empty={<EmptyState title={t("packagesPage.noImageContainsIt")}>{t("packagesPage.nothingMatchesThisNameAnd")}</EmptyState>}
          />
        </Panel>
      )}
    </>
  );
}

const lines = (s: string) =>
  s
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

function PolicyPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [saved, setSaved] = useState<Policy>();
  const [p, setP] = useState<Policy>();
  const [identities, setIdentities] = useState("");
  const [issuers, setIssuers] = useState("");
  const [allow, setAllow] = useState("");
  const [deny, setDeny] = useState("");
  const [error, setError] = useState<string>();
  const [done, setDone] = useState(false);
  const show = (x: Policy) => (
    setSaved(x),
    setP(x),
    setIdentities(x.allowedIdentities.join("\n")),
    setIssuers(x.allowedIssuers.join("\n")),
    setAllow(x.licenceAllow.join("\n")),
    setDeny(x.licenceDeny.join("\n"))
  );
  useEffect(() => void call<Policy>("/api/v1/policy").then(show, () => {}), [call]);

  const save = async () => {
    if (!p) return;
    try {
      show(
        await call<Policy>("/api/v1/policy", {
          method: "PUT",
          body: JSON.stringify({
            ...p,
            allowedIdentities: lines(identities),
            allowedIssuers: lines(issuers),
            licenceAllow: lines(allow),
            licenceDeny: lines(deny),
          }),
        }),
      );
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
      <PageHeader title={t("policyPage.policy")} description={t("policyPage.whatEveryImageMustShow")} />
      {p && (
        <>
          <Panel title={t("policyPage.signature")} description={t("policyPage.ciRunsCosignVerifyAnd")}>
            <div className="flex flex-col gap-3">
              <Switch
                checked={p.requireSignature}
                onCheckedChange={(v) => (setP({ ...p, requireSignature: v }), setDone(false))}
                label={t("policyPage.requireAVerifiedSignature")}
                disabled={readOnly}
              />
              {area(
                "Allowed signer identities",
                "One regular expression per line. The signer's identity must match one. Empty: any identity.",
                identities,
                setIdentities,
              )}
              {area(
                "Allowed issuers",
                "One exact issuer per line, such as https://token.actions.githubusercontent.com. Empty: any issuer.",
                issuers,
                setIssuers,
              )}
            </div>
          </Panel>
          <Panel title={t("policyPage.sbomAndProvenance")}>
            <div className="flex flex-col gap-3">
              <Switch
                checked={p.requireSbom}
                onCheckedChange={(v) => (setP({ ...p, requireSbom: v }), setDone(false))}
                label={t("policyPage.requireAnSbom")}
                disabled={readOnly}
              />
              <Switch
                checked={p.requireProvenance}
                onCheckedChange={(v) => (setP({ ...p, requireProvenance: v }), setDone(false))}
                label={t("policyPage.requireProvenance")}
                disabled={readOnly}
              />
              <SelectField
                label={t("policyPage.lowestSlsaBuildLevel")}
                value={String(p.minProvenanceLevel)}
                onChange={(e) => (setP({ ...p, minProvenanceLevel: Number(e.target.value) }), setDone(false))}
                disabled={readOnly}
                options={[0, 1, 2, 3, 4].map((n) => ({ value: String(n), label: n === 0 ? t("policyPage.any") : t("policyPage.level", { n }) }))}
              />
            </div>
          </Panel>
          <Panel title={t("policyPage.licences")} description={t("policyPage.spdxIdsAnOrExpression")}>
            <div className="grid gap-3 sm:grid-cols-2">
              {area("Allowed", "One id per line. Empty: any licence that is not denied.", allow, setAllow)}
              {area("Denied", "One id per line, such as AGPL-3.0-only.", deny, setDeny)}
            </div>
          </Panel>
          {can("admin") ? (
            <div className="flex items-center gap-3">
              <Button variant="primary" onClick={() => void save()} disabled={!saved}>
                {t("policyPage.savePolicy")}
              </Button>
              {done && <StatusBadge tone="success">{t("policyPage.saved")}</StatusBadge>}
              {error && <span className="text-xs text-danger">{error}</span>}
            </div>
          ) : (
            <p className="m-0 text-sm text-fg-muted">{t("policyPage.onlyAdminsChangeThePolicy")}</p>
          )}
        </>
      )}
    </>
  );
}

function ExceptionsPage({ call, reload }: { call: Call; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [rows, setRows] = useState<Exception[]>();
  const load = useCallback(
    () =>
      void call<{ exceptions: Exception[] }>("/api/v1/exceptions").then(
        (r) => setRows(r.exceptions),
        () => setRows([]),
      ),
    [call],
  );
  useEffect(load, [load]);
  const columns: Column<Exception>[] = [
    {
      id: "name",
      header: t("exceptionsPage.image"),
      cell: (e) => (
        <span className="supply-wrap">
          {e.name}
          {e.digest ? <span className="font-mono text-xs text-fg-muted"> {short(e.digest)}</span> : ""}
        </span>
      ),
    },
    { id: "rule", header: t("exceptionsPage.waives"), cell: (e) => <Badge>{RULE_LABEL(t)[e.rule]}</Badge> },
    { id: "reason", header: t("exceptionsPage.reason"), width: "34%", cell: (e) => <span className="text-xs">{e.reason}</span> },
    { id: "by", header: t("exceptionsPage.by"), cell: (e) => <span className="text-xs">{e.by ?? "–"}</span> },
    {
      id: "expires",
      header: t("exceptionsPage.ends"),
      sortValue: (e) => e.expiresAt,
      cell: (e) => <span className="text-xs whitespace-nowrap">{new Date(e.expiresAt).toLocaleDateString()}</span>,
    },
    {
      id: "state",
      header: t("exceptionsPage.state"),
      cell: (e) =>
        e.active ? (
          <StatusBadge tone="success">{t("exceptionsPage.active")}</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">{t("exceptionsPage.ended")}</StatusBadge>
        ),
    },
    {
      id: "remove",
      header: <span className="sr-only">{t("exceptionsPage.remove")}</span>,
      label: t("exceptionsPage.remove"),
      align: "right",
      cell: (e) =>
        can("editor") && (
          <IconButton
            label={t("exceptionsPage.removeTheExceptionFor", { name: e.name })}
            size="sm"
            onClick={() => void call(`/api/v1/exceptions/${e.id}`, { method: "DELETE" }).then(() => (load(), reload()))}
          >
            <Trash2 />
          </IconButton>
        ),
    },
  ];
  return (
    <>
      <PageHeader title={t("exceptionsPage.exceptions")} description={t("exceptionsPage.aRuleWaivedForAn")} />
      <Panel flush>
        <DataTable
          label={t("exceptionsPage.exceptions")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(e) => e.id}
          minWidth={900}
          empty={<EmptyState title={t("exceptionsPage.noExceptions")}>{t("exceptionsPage.everyRuleAppliesToEvery")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.ciReportsWhatItKnows")} />
      <Panel title={t("setupPage.reportAnImage")} description={t("setupPage.useSupplyChainIngestToken")}>
        <Code>{`digest=$(crane digest ghcr.io/acme/app:1.4.2)
syft ghcr.io/acme/app@$digest -o cyclonedx-json > sbom.json
cosign verify ghcr.io/acme/app@$digest \\
  --certificate-identity-regexp '^https://github.com/acme/' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null && verified=true || verified=false
jq -n --slurpfile sbom sbom.json --argjson verified $verified '{sbom: $sbom[0], signature: {verified: $verified}}' |
  curl -sf -X POST -H "Authorization: Bearer $SUPPLY_CHAIN_INGEST_TOKEN" -H 'content-type: application/json' --data-binary @- \\
  "${origin}/api/v1/images?name=ghcr.io/acme/app&digest=$digest"`}</Code>
      </Panel>
      <Panel title={t("setupPage.askWhetherItMayRun")} description={t("setupPage.fromAnAdmissionWebhookOr")}>
        <Code>{`curl -sf -H "Authorization: Bearer $SUPPLY_CHAIN_INGEST_TOKEN" \\
  "${origin}/api/v1/images/check?name=ghcr.io/acme/app&digest=$digest" | jq -e .allowed`}</Code>
      </Panel>
      <Panel title={t("setupPage.whatThisProductDoesAnd")}>
        <ul className="supply-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>{t("setupPage.itRecordsTheSbomThe")}</li>
          <li>{t("setupPage.itDoesNotVerifySignatures")}</li>
          <li>{t("setupPage.itBuildsAndSignsNothing")}</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first image arrives. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  const t = useT();
  return (
    <>
      <PageHeader
        title={t("welcomePage.getStarted")}
        description={t("welcomePage.reportAnImageFromCi")}
        actions={<StatusBadge tone="info">{t("welcomePage.waitingForTheFirstImage")}</StatusBadge>}
      />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdminOfThis")}</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: [
      "Members",
      "Who can sign in to this supply-chain, and with which role. Viewers see everything; editors also add exceptions; admins also change the policy, delete images, and manage members and tokens.",
    ],
    signin: [
      "Sign-in",
      "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role.",
    ],
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
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(
          r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "supply-chain" && (PRODUCT_IDS as readonly string[]).includes(p.id)),
        ),
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
    { id: "images", label: msg("product.images"), icon: Images, count: summary?.images },
    { id: "packages", label: msg("product.whereUsed"), icon: PackageSearch },
    { id: "policy", label: msg("product.policy"), icon: ScrollText },
    { id: "exceptions", label: msg("product.exceptions"), icon: ShieldOff, count: summary?.activeExceptions },
  ];
  const footerNav = [
    { id: "setup", label: msg("product.setup"), icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
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
