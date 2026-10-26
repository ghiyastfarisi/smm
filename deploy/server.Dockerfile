# smm server (AGPL) with at-rest encryption. Build context: ../server
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
# The stock Mattermost web app (release 1.0.0-rc.1 serves the unmodified client at /): build webapp/ and
# copy webapp/channels/dist to server/client before building this image (module 31, STOCK-01).
COPY --from=build /src/client /mattermost/client
USER mm
ENV PATH=/mattermost/bin:$PATH MMCTL_LOCAL_SOCKET_PATH=/mattermost/data/mattermost_local.socket
EXPOSE 8065
HEALTHCHECK --interval=5s --timeout=3s --start-period=20s --retries=30 CMD curl -sf http://localhost:8065/api/v4/system/ping || exit 1
CMD ["mattermost", "--config", "/mattermost/config/config.json"]
