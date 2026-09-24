# spitter
Flexible Webhook router for Prometheus Alertmanager webhook alerts

Alertmanager posts its native (version 4) webhooks to spitter at `/v4/alertmanager/webhook`.  Each configured router
matches alerts by label, renders them through a Go template (with [sprig](https://masterminds.github.io/sprig/)
functions) and sends the result to its own destination URL.  Links inside alerts are rewritten onto externally
reachable Alertmanager/Prometheus URLs along the way.  See [`examples/webhook_server.yml`](examples/webhook_server.yml)
for a config file with routers, and [`PROMETHEUS-METRICS.md`](PROMETHEUS-METRICS.md) for the metrics it exports.

## Router authentication and TLS

Each router can authenticate to its destination and choose how the destination's certificate is checked:

```yaml
routers:
- url: https://receiver.example.com/hook
  auth:
    token: s3cret                # "Authorization: Bearer s3cret"
    # tokenFile: /path/to/token  # same, read from a file (surrounding whitespace is trimmed)
    # basicAuth:                 # "Authorization: Basic ..."
    #   username: spitter
    #   password: s3cret
    # cookies: {session: abc123}
  tls:
    caFile: /etc/spitter/receiver-ca.pem  # trust only this PEM CA bundle instead of the system roots
    # insecureSkipVerify: true            # accept any certificate; disables verification entirely
  template: ...
  matchers: ...
```

HTTPS certificates are verified against the system CA roots unless `tls` says otherwise.  Earlier versions of
spitter never verified them, so a router pointing at a self-signed endpoint now fails until it sets `tls.caFile`
(preferred) or `tls.insecureSkipVerify: true`.  A router whose `caFile` cannot be read or holds no certificates is
rejected at load time, like one whose `tokenFile` is missing.  Each outbound webhook times out after 30 seconds.

## Building

```sh
go test ./...
go build -o spitter .
```

## Container image

The [`Dockerfile`](Dockerfile) produces a static binary on a distroless, non-root base image (no shell).  It
cross-compiles, so multi-arch builds need no emulation:

```sh
docker build -t spirilis/spitter:dev .
docker buildx build --platform linux/amd64,linux/arm64 -t spirilis/spitter:0.2.0 --push .
```

The image runs `spitter router` by default.  Mount a config file, or configure it with flags or environment
variables:

```sh
docker run --rm -p 9820:9820 -v "$PWD/examples:/config:ro" spirilis/spitter:dev \
  router --config /config/webhook_server.yml

docker run --rm -p 9820:9820 -v "$PWD/routers:/routers:ro" \
  -e SPITTER_ALERTMANAGER_URL=https://alertmanager.example.com \
  -e SPITTER_PROMETHEUS_URL=https://prometheus.example.com \
  -e SPITTER_ROUTERS_DIR=/routers \
  -e SPITTER_ROUTERS_WATCH_INTERVAL=10s \
  spirilis/spitter:dev
```

| Flag | Environment variable | Purpose |
| --- | --- | --- |
| `--config` | `SPITTER_CONFIG` | Config file (listen address, URLs, routers, metrics path). |
| `--alertmanager` | `SPITTER_ALERTMANAGER_URL` | External Alertmanager base URL; overrides the config file. |
| `--prometheus` | `SPITTER_PROMETHEUS_URL` | External Prometheus base URL; overrides the config file. |
| `--routers` | `SPITTER_ROUTERS_DIR` | Directory of additional router documents, one per file. |
| `--routers-watch-interval` | `SPITTER_ROUTERS_WATCH_INTERVAL` | Poll the routers directory and reload on change (e.g. `10s`). |
| `--reload-trigger` | `SPITTER_RELOAD_TRIGGER` | Reload routers when this file appears, then delete it. |

Routers are also reloaded on `SIGHUP`.  `spitter dump` runs a small server that prints every request it receives,
which is handy as a webhook destination while developing templates.

## Kubernetes

A Helm chart lives in [`helm/spitter`](helm/spitter).  It can expose spitter through a ClusterIP, NodePort or
LoadBalancer Service, an Ingress, or a Gateway API HTTPRoute, and hot-reloads routers kept in a ConfigMap or
Secret.  See the [chart README](helm/spitter/README.md).

```sh
helm install spitter ./helm/spitter -n monitoring -f my-values.yaml
```
