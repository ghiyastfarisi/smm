# smm server (AGPL) with at-rest encryption. Build context: ../server, named context `webapp`: ../webapp
# (docker-compose.yml sets both), so `docker compose build server` builds everything from a fresh clone.

# The stock Mattermost web app, served at / (STOCK-01). Source maps are left out of the image (SEC-09).
FROM node:24.11.1-bookworm AS web
WORKDIR /webapp
COPY --from=webapp . .
RUN --mount=type=cache,target=/root/.npm \
    npm ci --no-audit --no-fund --engine-strict=false && npm run build && find channels/dist -name '*.map' -delete

FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY public/go.mod public/go.sum ./public/
# go.work is gitignored upstream (make setup-go-work); create it so a fresh clone builds.
RUN go work init . ./public
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/mattermost ./cmd/mattermost && \
    CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/mmctl ./cmd/mmctl   # -trimpath: same binary from any checkout path (OPS-15)

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl tzdata && rm -rf /var/lib/apt/lists/* \
 && useradd -u 2000 -m mm && mkdir -p /mattermost/config /mattermost/data && chown -R mm /mattermost
WORKDIR /mattermost
COPY --from=build /out/ /mattermost/bin/
COPY --from=build /src/i18n /mattermost/i18n
COPY --from=build /src/templates /mattermost/templates
COPY --from=build /src/fonts /mattermost/fonts
COPY --from=web /webapp/channels/dist /mattermost/client
# COPY keeps the checkout's modes; a clone made with umask 077 would leave these unreadable for the mm user.
RUN chmod -R a+rX /mattermost/bin /mattermost/i18n /mattermost/templates /mattermost/fonts /mattermost/client
USER mm
ENV PATH=/mattermost/bin:$PATH MMCTL_LOCAL_SOCKET_PATH=/mattermost/data/mattermost_local.socket
EXPOSE 8065
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --retries=30 CMD curl -sf http://localhost:8065/api/v4/system/ping || exit 1
CMD ["mattermost", "--config", "/mattermost/config/config.json"]
