# smm — Secure Mattermost (codename)

smm is an independent fork of the open-source [Mattermost](https://github.com/mattermost/mattermost) server and
clients, extended with security:

- **Encryption at rest** — messages, files, drafts, channel headers and purposes, user PII and tokens are sealed with
  AES-256-GCM before they reach the database or file store. Every team/channel (and every DM) has its own derived
  key, and each value is bound by AEAD to its team, channel, table, column and row.
- **Key management** — the root key lives only in [OpenBAO](https://openbao.org): sealed storage, Shamir 3-of-5
  unseal, read-only AppRole, audit log. The server fails closed when the KMS is sealed.
- **Search without plaintext** — HMAC blind-index tokens.
- **Hardening** — no calls to Mattermost, Inc. services, generic push contents, hashed session tokens, locked release
  configuration, TLS edge with IP allow-list.

The stock Mattermost web, desktop and mobile apps work unchanged against the smm server. This repository holds the
server fork, the KMS and the deployment; it ships no client builds.

> smm is **not affiliated with, endorsed by, or sponsored by Mattermost, Inc.** "Mattermost" is a trademark of
> Mattermost, Inc. Attribution and licences: [NOTICE.md](NOTICE.md).

## Documentation
| | |
|---|---|
| Architecture, how smm extends Mattermost, security and encryption design | [docs/smm/ARCHITECTURE.md](docs/smm/ARCHITECTURE.md) |
| Step by step: install, KMS, security demo, production hardening, operations | [docs/smm/STEP-BY-STEP.md](docs/smm/STEP-BY-STEP.md) |
| Encryption proof and coverage | [docs/smm/ENCRYPTION.md](docs/smm/ENCRYPTION.md) |
| KMS operations | [deploy/openbao/README.md](deploy/openbao/README.md) |

## Install on a VM
```bash
git clone -b smm https://github.com/ghiyastfarisi/smm.git && cd smm
bash deploy/install.sh                  # pulls ghcr.io/ghiyastfarisi/smm; needs git, Docker, openssl; KMS on
```
Open the address it prints and create the first account (it becomes the system admin). Details and production
hardening: [docs/smm/STEP-BY-STEP.md](docs/smm/STEP-BY-STEP.md#quick-install-on-a-vm-one-command).

## Quick start (local demo)
```bash
git clone -b smm https://github.com/ghiyastfarisi/smm.git && cd smm
node deploy/build-stock-client.mjs
bash deploy/up.sh                       # creates deploy/.env, builds, starts, seeds demo users
node deploy/prove-encryption.mjs        # "all checks passed: data at rest is encrypted"
```
Open http://localhost:8065 and log in as `ani` / `Demo#12345`. Production setup: [docs/smm/STEP-BY-STEP.md](docs/smm/STEP-BY-STEP.md).

## Repository layout
| Path | What | Licence |
|---|---|---|
| `server/`, `webapp/`, … | Mattermost server and web app with the smm changes | AGPL v3.0 / Apache 2.0 (upstream, see `LICENSE.txt`) |
| `deploy/` | Docker Compose, OpenBAO KMS setup, TLS edge, backup, proof scripts | AGPL v3.0 |
| `docs/smm/` | smm documentation (the rest of `docs/` is upstream's) | AGPL v3.0 |

## Licence
Code written for smm is licensed under the [GNU AGPL v3.0](LICENSE.txt); upstream files keep their licences. If you
run a modified smm server for users over a network, AGPL v3.0 §13 requires you to offer them its source; see
[NOTICE.md](NOTICE.md#source-code-offer-agpl-v30-13).
