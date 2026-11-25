# spitter
Flexible Webhook router for Prometheus Alertmanager webhook alerts

Alertmanager posts its native (version 4) webhooks to spitter at `/v4/alertmanager/webhook`.  Each configured router
matches alerts by label, renders them through a Go template (with [sprig](https://masterminds.github.io/sprig/)
functions) and sends the result to its own destination URL.  Links inside alerts are rewritten onto externally
reachable Alertmanager/Prometheus URLs along the way.  See [`examples/webhook_server.yml`](examples/webhook_server.yml)
for a config file with routers, and [`PROMETHEUS-METRICS.md`](PROMETHEUS-METRICS.md) for the metrics it exports.

## Receiving webhooks

Point an Alertmanager `webhook_config` at `http://<spitter>:9820/v4/alertmanager/webhook`.  The payload must be
Alertmanager's own JSON, version 4; spitter answers `400` to anything else, which Alertmanager treats as final.
Once a payload is accepted the answer is `200`, whether or not every router's destination took its webhook:
failures are logged as warnings and show in the [metrics](PROMETHEUS-METRICS.md), but are not retried.

A router receives a notification when at least one alert in the group satisfies **all** of its matchers, and it
receives only those alerts.  `match` compares the label's value exactly; `match_re` is an unanchored regular
expression, so `crit` also matches `critical`.

The endpoint has no authentication.  Keep it reachable by Alertmanager only: the Helm chart does this with a
NetworkPolicy.

## Template data

Each router's template is a Go [`text/template`](https://pkg.go.dev/text/template) with the sprig functions.  It
receives the Alertmanager v4 webhook, with these fields:

| Field | Notes |
| --- | --- |
| `.Version`, `.GroupKey`, `.TruncatedAlertCount`, `.Receiver` | As sent by Alertmanager (`truncatedAlerts` becomes `.TruncatedAlertCount`). |
| `.Status` | `firing` or `resolved`.  When the router receives only some of the group's alerts, it describes those: `firing` if any of them is. |
| `.GroupLabels`, `.CommonLabels`, `.CommonAnnotations` | Maps. |
| `.RouteLabels` | Map of the matching route's rendered `labels:` (Alertmanager 0.34+; empty before). |
| `.NotificationReason` | Why Alertmanager sent it: `first notification`, `new alerts added`, `some alerts resolved`, `all alerts resolved`, `repeat interval elapsed` or `unknown` (Alertmanager 0.32+; empty before). |
| `.ExternalURL` / `.OriginalExternalURL` | Alertmanager link rewritten onto the configured Alertmanager URL / as sent. |
| `.Env` | The process environment.  Anything in it, secrets included, can be rendered into a payload. |
| `.Alerts` | Only the alerts that match this router's matchers. |

Each alert has `.Status`, `.Labels` and `.Annotations` (with the common ones merged in), `.StartsAt` and `.EndsAt`
(RFC3339 strings; use sprig's `toDate` to format them), `.GeneratorURL` / `.OriginalGeneratorURL` (rewritten onto
the configured Prometheus URL / as sent) and `.Fingerprint`.

### Building JSON

Write values into a JSON payload with sprig's `toJson`, which adds the quotes and escaping and also takes whole maps:

```
{"status": {{ .Status | toJson }}, "summary": {{ .CommonAnnotations.summary | toJson }}, "labels": {{ .CommonLabels | toJson }}}
```

Do not put a value between quotes yourself (`"{{ .CommonAnnotations.summary }}"`).  One quote or newline in the text
breaks the payload, and whoever writes the alert's text can then add fields of their own.  `{{ . | toJson }}` prints
the whole payload; `.Env` is left out of it.

## Router authentication and TLS

Each router can authenticate to its destination and choose how the destination's certificate is checked:

```yaml
routers:
- url: https://receiver.example.com/hook
  auth:
    token: s3cret                # "Authorization: Bearer s3cret"
    # tokenFile: /path/to/token  # same, read from the file for every webhook (surrounding whitespace is trimmed)
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
(preferred) or `tls.insecureSkipVerify: true`.  Each outbound webhook times out after 30 seconds.

Set only one of `token`, `tokenFile` and `basicAuth`.  Because `tokenFile` is read for every webhook, a token that
is rotated on disk is picked up without a reload; if the file is missing or empty at that moment, the webhook is not
sent.

## Router validation

Routers are checked when they are loaded, at startup and on every reload.  A router that fails is left out, logged
as a warning and counted in `spitter_webhook_routers_rejected`; the others keep working.  A router is rejected when:

- its `url` is not an `http://` or `https://` address with a host, or its `method` is not a valid HTTP method;
- its `template` does not parse;
- it has no matchers, or a matcher has no `label`, has neither `match` nor `match_re`, or has an invalid `match_re`;
- its `auth` sets more than one of `token`, `tokenFile` and `basicAuth`, or a `basicAuth` password without a username;
- its `tokenFile` or `tls.caFile` cannot be read, or the `caFile` holds no certificates;
- its document has a key spitter does not know, or the same key twice.  A misspelled `auth:` or `tls:` would
  otherwise be dropped and the router sent without its credentials.

The config file itself is read the same way: an unknown key stops spitter at startup.  If no router at all is
valid, spitter exits, at startup and on a reload alike.

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
| `--log-level` | `SPITTER_LOG_LEVEL` | `trace`, `debug`, `info` or `warning`; also `logLevel:` in the config file.  Default `trace`. |

`trace` logs request headers, alert payloads, rendered templates and destination responses, any of which can hold
secrets; `info` is the level to run with once your templates work.  Destination URLs appear in warnings at every
level.

Routers are also reloaded on `SIGHUP`.  `spitter dump` runs a small server that prints every request it receives,
which is handy as a webhook destination while developing templates.

## Kubernetes

A Helm chart lives in [`helm/spitter`](helm/spitter).  It can expose spitter through a ClusterIP, NodePort or
LoadBalancer Service, an Ingress, or a Gateway API HTTPRoute, and hot-reloads routers kept in a ConfigMap or
Secret.  See the [chart README](helm/spitter/README.md).

```sh
helm install spitter ./helm/spitter -n monitoring -f my-values.yaml
```
