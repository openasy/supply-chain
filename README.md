# supply-chain

[![CI](https://github.com/openasy/supply-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/supply-chain/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Supply Chain product: **what CI knows about every image, and a policy that says
which may run** (ADR 0043). CI reports an image's SBOM, the result of its own signature check and a provenance summary.
supply-chain keeps them, judges every image against one policy, and answers a Kubernetes admission webhook or a pipeline
that asks whether an image may run.

```
CI: syft, cosign verify ──POST /api/v1/images──▶  supply-chain  ◀──GET /api/v1/images/check── webhook, pipeline
                                                  SBOMs, evidence, policy, exceptions        { allowed, reasons }
```

> **It records what CI says; it does not verify signatures or provenance itself.** This first release trusts the token
> that sends evidence like it trusts the pipeline that holds it. It builds and signs nothing. Checking signatures against
> the transparency log in the product, and admission control inside the cluster, come next (ADR 0043).

## The policy

One policy for the installation, edited under Policy by admins and applied to every image at once:

- **Signature.** Require a verified signature, optionally from signers whose identity matches one of your regular
  expressions and whose issuer is one you name.
- **SBOM and provenance.** Require an SBOM, and provenance of at least a SLSA build level.
- **Licences.** An allow list and a deny list of SPDX ids. An `OR` expression passes when one alternative does
  (`GPL-3.0-only OR MIT` is fine when MIT is allowed); an `AND` needs every part. `GPL-2.0+` and `GPL-2.0` are the same
  entry, and case does not matter. With an allow list, a package whose licence nobody named is denied. A CycloneDX
  entry that lists several licences is read as `AND`, the stricter reading.

An **exception** waives one rule, or all, for an image name or one digest, with a reason and an end within a year. The
answer to a webhook still lists what was waived. An image nobody reported on is **denied**.

## Run

```bash
openssl rand -hex 32 > openasy-kek
export SUPPLY_CHAIN_INGEST_TOKEN=$(openssl rand -hex 32)
docker compose up -d
docker compose logs supply-chain | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/.

Report an image from CI, with any of the three kinds of evidence:

```bash
digest=$(crane digest ghcr.io/acme/app:1.4.2)
syft ghcr.io/acme/app@$digest -o cyclonedx-json > sbom.json
cosign verify ghcr.io/acme/app@$digest --certificate-identity-regexp '^https://github.com/acme/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null && verified=true || verified=false
jq -n --slurpfile sbom sbom.json --argjson verified $verified '{sbom: $sbom[0], signature: {verified: $verified}}' |
  curl -sf -X POST -H "Authorization: Bearer $SUPPLY_CHAIN_INGEST_TOKEN" -H 'content-type: application/json' --data-binary @- \
  "https://supply-chain.example.com/api/v1/images?name=ghcr.io/acme/app&digest=$digest"
```

What is not sent stays as it was; a new SBOM replaces the old one. The body may be gzipped, up to 128 MiB unpacked.
Ask whether an image may run:

```bash
curl -sf -H "Authorization: Bearer $SUPPLY_CHAIN_INGEST_TOKEN" \
  "https://supply-chain.example.com/api/v1/images/check?name=ghcr.io/acme/app&digest=$digest" | jq -e .allowed
```

`Where used` finds every image that contains a package, for the day a library turns out to be vulnerable.

`openasy-kek` encrypts sign-in secrets in the database (ADR 0021). Keep it apart from the volume and with your backups.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `SUPPLY_CHAIN_PUBLIC_URL` | `http://localhost:8080` | The address people open, with `https://` behind your TLS proxy |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher. Give every product the same value |
| `SUPPLY_CHAIN_INGEST_TOKEN` | | Lets CI and the webhook send evidence and ask for answers, nothing else. An API token works too |
| `SUPPLY_CHAIN_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `SUPPLY_CHAIN_DB` | `/data/supply-chain.db` | SQLite file (WAL), on the `/data` volume |
| `SUPPLY_CHAIN_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `SUPPLY_CHAIN_HEADLESS` | `false` | `true` serves only the API |
| `SUPPLY_CHAIN_PASSWORD_SIGN_IN`, `SUPPLY_CHAIN_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)). Owners can also add identity providers under Settings, Sign-in |

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see everything; editors also add and remove exceptions; admins also change the policy, delete images, and manage
members and API tokens (ADR 0003). The ingest token, and an API token with any role, can ask whether an image may run.

## Develop

```bash
npm install
npm test        # SPDX expressions, SBOM parsing, the policy and exceptions, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
