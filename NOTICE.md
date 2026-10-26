# NOTICE — attribution and licences

**smm** (Secure Mattermost, codename) is an independent fork of the open-source Mattermost platform, extended with
encryption at rest, a key management service and security hardening.

**smm is not affiliated with, endorsed by, or sponsored by Mattermost, Inc.** "Mattermost" is a trademark of
Mattermost, Inc. It is used here only to say truthfully where the code comes from. smm does not use the Mattermost
logo and is not presented as a Mattermost product. Any other use of the mark needs Mattermost, Inc.'s prior written
approval ([trademark standards of use](https://mattermost.com/trademark-standards-of-use/)).

## Upstream projects

| Component in this repository | Upstream | Copyright | Licence | Changed by smm |
|---|---|---|---|---|
| this repository (server, web app, mmctl) | [mattermost/mattermost](https://github.com/mattermost/mattermost), forked at `8a378be804` | © 2015-present Mattermost, Inc. | Server and other source: **GNU AGPL v3.0**. `webapp/`, `server/templates/`, `server/i18n/`, `server/public/` (Admin Tools and Configuration Files): **Apache License 2.0**. See [`LICENSE.txt`](LICENSE.txt) | yes, see below |
| OpenBAO (container image `openbao/openbao:2.5.0`, not vendored) | [openbao/openbao](https://github.com/openbao/openbao) | © The OpenBao Authors | Mozilla Public License 2.0 | no |
| PostgreSQL, nginx (container images, not vendored) | upstream images | their authors | PostgreSQL Licence, BSD-2-Clause | no |

Each upstream directory keeps its own `LICENSE.txt` and `NOTICE.txt` (third-party notices) unchanged. Those files,
and the copyright headers in every source file, must be kept in any copy or redistribution.

## What smm changed

**Server and web app (branch `smm`):**
- Encryption at rest: AES-256-GCM for messages, hashtags, drafts, scheduled posts, channel headers and purposes,
  file names, file contents, user PII, audits and integration tokens; per-team/per-channel keys derived with HKDF;
  AAD binding each value to its channel, table, column and row; HMAC blind-index search
  (`server/channels/store/sqlstore/{post,pii,channel}_crypto.go`, `server/platform/shared/filestore/encrypted.go`,
  `server/platform/shared/keyring/`), with migrations `000235`…`000241`.
- Key custody in OpenBAO (AppRole, fail-closed start), session and personal access tokens stored hashed, log
  redaction, native OpenID Connect provider (`server/channels/app/oauthproviders/openid/`).
- **Removed** the source-available `server/enterprise/` directory and everything that compiled it in. No code under
  the Mattermost Source Available License is built into smm. (`LICENSE.enterprise` is kept only because it is part of
  the upstream tree; it applies to no code that smm builds.)
- Rebranding of end-user strings, logo and favicons (no Mattermost logo is shipped).


**New code in this repository** (`deploy/`, `docs/smm/`): deployment, KMS setup, proof scripts and documentation, written
for smm.

## Licence of this repository

- Code written for smm in this repository is licensed under the **GNU AGPL v3.0** ([`LICENSE.txt`](LICENSE.txt)).
- Upstream files keep their licences (table above); smm's changes to them are released under
  the same licences.
- Apache 2.0 §4(b): modified files carry a notice of change in the commit history of branch
  `smm` (one commit on top of upstream `8a378be804`) and in this NOTICE.

## Source code offer (AGPL v3.0 §13)

If you run a modified smm server for users over a network, you must offer those users the complete corresponding
source code of the version you run. The source of smm is published at:

- `https://github.com/ghiyastfarisi/smm`, branch `smm` (tags `v1.0.0-rc.5` and later)

The About dialog and the login page footer should link to these addresses.

## No warranty

smm is provided "as is", without warranty of any kind, as stated in the AGPL v3.0 (§15–16) and the Apache License
2.0 (§7–8). Encryption at rest protects data stored in the database and file store; it is not end-to-end
encryption. See [`docs/smm/ARCHITECTURE.md`](docs/smm/ARCHITECTURE.md) §6 for what is not covered.
