# syntax=docker/dockerfile:1

# Multi-arch friendly: the build stage always runs on the builder's native platform and cross-compiles, e.g.
#   docker buildx build --platform linux/amd64,linux/arm64 -t spirilis/spitter:0.2.0 --push .

ARG GO_VERSION=1.27

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/spitter .

# distroless/static ships CA certificates and tzdata, runs as uid/gid 65532 and contains no shell
FROM gcr.io/distroless/static-debian13:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="spitter" \
      org.opencontainers.image.description="Flexible templating webhook router for Prometheus Alertmanager" \
      org.opencontainers.image.source="https://github.com/spirilis/spitter" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/spitter /usr/local/bin/spitter

USER 65532:65532
EXPOSE 9820

ENTRYPOINT ["/usr/local/bin/spitter"]
CMD ["router"]
