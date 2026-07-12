# Third-Party Notices

> Status: **engineering draft — legal approval required before distribution**  
> Generated: 2026-07-12  
> Scope: locked Web and Python production application dependencies

This file records third-party components detected by automated tooling. It is not a license grant for this project, is not legal advice, and is not a substitute for the complete upstream license texts that must accompany the final distribution.

## Project licensing status

The root applications `enterprise-knowledge-base-web@0.1.0` and `enterprise-knowledge-base@0.1.0` do not currently declare a project license. The Web scanner reports the root package as `UNLICENSED`; both CycloneDX root components have no `licenses` value. The `private: true` npm flag is a publishing control, not a license.

No recipient should infer a right to copy, redistribute, sublicense, or modify the project itself from this notice. The copyright owner and legal team must select and add the project's governing license before external delivery.

## Complete machine-readable inventories

- `artifacts/acceptance/sbom-web.cdx.json` — CycloneDX 1.6 JSON, SHA-256 `A90A51571435CA05986F976F9CAAADF2F5CF8F3435534D485272D7EFC0DEC5DF`
- `artifacts/acceptance/sbom-python.cdx.json` — CycloneDX 1.6 JSON, SHA-256 `F9556EF2DC12E2B9C72B31962F48A91BFAE4FCE048952DDCAA341957670800FA`
- `DEPENDENCY_LICENSE_AUDIT.zh-CN.md` — generation commands, tool versions, counts, limitations, and release blockers

The SBOMs are the exhaustive package/version inventories for this audit snapshot. This notice highlights obligations that require explicit release review and groups permissive components for readability.

## Components requiring explicit release review

### libvips / sharp platform binaries

- Components: `@img/sharp-*`, `@img/sharp-libvips-*`, and the platform package selected in the final runtime image
- Detected expressions: `Apache-2.0 AND LGPL-3.0-or-later` and `LGPL-3.0-or-later`
- Upstream project: <https://github.com/lovell/sharp>
- Required action: retain the applicable license and copyright notices; identify the exact binary selected in the Linux production image; determine, with legal review, the LGPL source/relinking obligations for the actual distribution and any modifications.

The lock-file SBOM intentionally includes optional packages for multiple operating systems. Only a scan of the built production image can establish which platform binary is delivered.

### Psycopg

- Components: `psycopg 3.3.4`, `psycopg-binary 3.3.4`
- Detected expression: `LGPL-3.0-only`
- Upstream project: <https://www.psycopg.org/>
- Required action: include the exact upstream LGPL text and retained notices; record whether either package or bundled binary was modified; obtain legal approval for the chosen distribution method.

### certifi

- Component: `certifi 2026.6.17`
- Detected expression: `MPL-2.0`
- Upstream project: <https://github.com/certifi/python-certifi>
- Required action: retain the MPL license and file-level notices, and record any modifications to covered files. This audit found no evidence of repository modifications to certifi, but the final built image must be checked.

### caniuse-lite

- Component: `caniuse-lite 1.0.30001803`
- Detected expression: `CC-BY-4.0`
- Upstream project and attribution source: <https://github.com/browserslist/caniuse-lite>
- Attribution statement: This product includes browser compatibility data from the `caniuse-lite` project, licensed under Creative Commons Attribution 4.0 International.
- Modification statement for this audit snapshot: no intentional modification to the upstream package was identified; npm packaging and bundling may mechanically transform files.
- Required action: retain creator identification supplied upstream, this license reference, warranty disclaimer reference, and any modification indication required by the final form of distribution.

## Permissive and public-domain-style components

The following production components were reported under MIT, Apache-2.0, BSD, ISC, PSF, 0BSD, MIT-0, Unlicense, or combinations of these terms. Their notices and license texts must still be retained where the applicable license requires it.

### Web application

`@img/colour`, `@next/env`, `@next/swc-*`, `@swc/helpers`, `baseline-browser-mapping`, `client-only`, `detect-libc`, `nanoid`, `next`, `picocolors`, `postcss`, `react`, `react-dom`, `scheduler`, `semver`, `sharp`, `source-map-js`, `styled-jsx`, and `tslib`.

Development-only packages such as Playwright, axe, TypeScript, Vitest, ESLint, and type definitions are recorded by the lock file but are not intended to be copied into the standalone production image. Release engineering must verify that the final image actually excludes them.

### Python application

`alembic`, `annotated-doc`, `annotated-types`, `anyio`, `argon2-cffi`, `argon2-cffi-bindings`, `asyncpg`, `boto3`, `botocore`, `cffi`, `click`, `colorama`, `cryptography`, `defusedxml`, `dnspython`, `email-validator`, `fastapi`, `greenlet`, `h11`, `hiredis`, `httpcore`, `httptools`, `httpx`, `idna`, `jmespath`, `Mako`, `MarkupSafe`, `pwdlib`, `pycparser`, `pydantic`, `pydantic-core`, `pydantic-settings`, `PyJWT`, `python-dateutil`, `python-dotenv`, `python-multipart`, `PyYAML`, `redis`, `s3transfer`, `six`, `SQLAlchemy`, `starlette`, `typing-extensions`, `typing-inspection`, `tzdata`, `urllib3`, `uvicorn`, `uvloop`, `watchfiles`, and `websockets`.

Environment markers mean that not every listed wheel is installed on every operating system. The production container SBOM remains authoritative for the shipped binary set.

## Notices not yet covered by this file

This draft does not inventory:

- Debian, Alpine, PostgreSQL, Redis, MinIO, Caddy, Node.js, Python, or other operating-system/container-image packages;
- cloud provider, model API, hosted database, or object storage commercial terms;
- company trademarks, logos, UI reference images, screenshots, documentation excerpts, uploaded customer content, or model-generated material;
- patent, export-control, data-license, privacy, or trademark obligations not represented in package metadata.

See `ASSET_PROVENANCE.zh-CN.md` for the visual-asset evidence gap.

## Distribution checklist

- [ ] Copyright owner and legal team approve the project-level license.
- [ ] Full exact license texts and upstream NOTICE files are collected from the final built artifacts.
- [ ] The Linux API and Web images receive image-level SBOM and license scans.
- [ ] LGPL, MPL, and CC-BY obligations are mapped to the actual distribution method and signed off.
- [ ] Third-party notices are bundled with both offline and online release packages.
- [ ] SBOMs, notices, source archive, image digests, and legal approval reference the same immutable release SHA.

Until every item is complete, this notice must remain marked as a draft and the legal gate remains **NO-GO**.
