# spitter

A templating webhook router for Prometheus Alertmanager. Alertmanager POSTs its native v4 webhook to
`/v4/alertmanager/webhook`. Each configured **router** decides by label matchers whether it wants the alert group,
renders it through a Go `text/template` (with sprig functions) and sends the result to its own destination URL.
Along the way, the Alertmanager and Prometheus links inside each alert are rewritten onto externally reachable base
URLs.

Module `github.com/spirilis/spitter`, Go 1.26 (`go.mod`); the Dockerfile builds with Go 1.27. MIT licensed.

## Commands

```sh
go test ./...                      # all tests; no network, no external services needed
go vet ./...
go build -o spitter .              # /spitter is gitignored
go test -race ./...                # the reload test only proves anything under the race detector
helm lint helm/spitter -f helm/spitter/ci/<x>-values.yaml   # clusterip, gateway, nodeport-ingress
docker buildx build --platform linux/amd64,linux/arm64 -t spirilis/spitter:<ver> .
```

The binary has two kong subcommands (`main.go`):

- `spitter router` (the image's default CMD) runs the router. It takes `--config`, `--alertmanager`,
  `--prometheus`, `--routers`, `--routers-watch-interval`, `--reload-trigger` and `--log-level`, each with a `SPITTER_*`
  environment variable. A flag or variable overrides the config file. With no `--config` at all, a built-in
  placeholder config is used, which is only useful for smoke testing.
- `spitter dump [--listen] [--port]` (`dump/`) runs a tiny server that prints every request to stdout. Point a
  router at it while developing templates.

## Layout

| Path | What it holds |
| --- | --- |
| `main.go` | CLI parsing, config file load (`loadConfigFile`, strict YAML), CLI overrides, then `WebhookServer.Start()`. |
| `logging.go` | Log levels (`tracef`, `debugf`, `infof`, `warnf`, `setLogLevel`). |
| `webhook_server.go` | Almost all the logic: `WebhookRouter` (+ `WebhookAuthentication`, `WebhookTLS`), `WebhookMatcher`, `WebhookServer` (config, reload, watchers, metrics, HTTP handlers). |
| `alerts/alertmanager.go` | Alertmanager v4 payload types, `Prepare()` → template data, and `URLReplacements` (link rewriting). Holds `GlobalRoutingConfig`. |
| `dump/` | The `dump` subcommand. |
| `examples/webhook_server.yml` | Reference config showing every router option. `examples/*_local.yml` is gitignored for personal configs. |
| `helm/spitter/` | Helm chart (see below). |
| `PROMETHEUS-METRICS.md` | Metric list. The `WebhookServer` section is implemented; the per-alert/per-label section is still only a proposal. |
| `*_test.go` | The handler end to end (`webhook_handler_test.go`), router validation, loading and reload (`router_load_test.go`), the documented examples (`examples_test.go`), log levels (`logging_test.go`), routing/filtering, send status handling, auth/TLS, router-dir checksum (`router_watch_test.go`), payload fields, templates and URL rewriting (`alerts/`). |

## Request flow

1. `handleWebhooksV4` accepts POST only and decodes the body with `encoding/json` into
   `alerts.AlertmanagerWebhookInputV4`. A body that is not JSON, or whose version is not `"4"`, gets a 400, which is
   final for Alertmanager. Null entries in `alerts` are dropped.
2. Each router from `GlobalWebhookServer.GetRouters()` goes through `routeWebhook`, behind a `recover` so that one
   router cannot stop the ones after it. A router is a candidate only when **every** matcher matches something:
   `CommonLabels` or any alert's labels (`HasMatchingAlerts`).
3. `PrepareTemplateData` calls `Prepare()`, which:
   - rejects anything but version `"4"`;
   - gives each alert **new** label and annotation maps with the common ones laid over its own (the payload itself
     is never written to: it is prepared once per matching router);
   - rewrites `ExternalURL` and `GeneratorURL` onto the configured bases (the originals stay in
     `OriginalExternalURL` and `OriginalGeneratorURL`);
   - exposes the process environment as `.Env`.

   If the common labels don't satisfy every matcher, alerts that don't individually satisfy all of them are
   **dropped** from `.Alerts` (`IsMatchingAlert`), and `.Status` is recomputed for what is left (`statusOf`). If
   nothing is left, the router sends nothing.
4. `SendWebhook` executes the router's parsed template and sends it with the router's method (default `POST`) and
   content type (default `application/yaml`). It adds the `Authorization` header (bearer token, token file or basic
   auth) and any cookies, and uses the router's `http.Client` (30s timeout, TLS settings). A `tokenFile` is read for
   every send. Only a 2xx response counts as success.
5. Routers run **sequentially**, and once the payload is accepted the handler answers 200 to Alertmanager. Send
   errors are only logged (as warnings) and reflected in the metrics.

Template data is `alerts.AlertmanagerWebhookTemplateV4` (field table in README "Template data"). It has
`.Status`, `.Receiver`, `.GroupLabels`, `.CommonLabels`, `.CommonAnnotations`, `.RouteLabels`,
`.NotificationReason`, `.ExternalURL`, `.OriginalExternalURL` and `.Env`. Its `.Alerts` each have
`.Status`, `.Labels`, `.Annotations`, `.StartsAt`, `.EndsAt`, `.GeneratorURL`, `.OriginalGeneratorURL` and
`.Fingerprint`.

What `toJson` prints is part of the template interface (`TestToJsonOfTemplateData`): `.Env` is left out of
`{{ . | toJson }}`, and alerts print with their Go field names because `AlertmanagerAlertV4` deliberately has no
`json` tags. Examples must build JSON with `toJson`, never by quoting values; `examples_test.go` renders them
against hostile alert text.

### Matchers

`{label, match}` is an exact match and `{label, match_re}` is a Go regexp. A regexp is unanchored, so `"crit"`
matches `"critical"`. If both are set, either one may match.

### Router loading and reload

`ReloadRouters()` builds a **new** router list from two sources:

- the inline `routers:` in the config file, copied with `clone()` on every reload;
- every file in `addlRouterDir`, one router document per file (YAML or JSON), decoded strictly.

Each router goes through `Check()` and then `prepare()`:

- `Check()` validates the URL, method, matchers and auth settings, and parses the template and regexps. The full
  list of rejections is in README "Router validation".
- `prepare()` applies defaults, checks the token file is readable and builds the HTTP client.

A loaded router is never changed again, which is what makes it safe to use from requests without locking. Rejected
routers, including files that cannot be read or parsed, are logged as warnings and counted in
`spitter_webhook_routers_rejected`. If no valid routers remain, reload returns an error. Reloads are serialized by
`reloadMutex`.

Reload is triggered by:

- `SIGHUP`;
- the `reloadTriggerFile` appearing (polled every 5s, then deleted);
- a change in the `addlRouterDir` content checksum, when `addlRouterDirWatchInterval` / `--routers-watch-interval`
  is greater than 0. The checksum follows symlinks, so a Kubernetes ConfigMap `..data` swap counts as a change.

**A reload that ends with zero valid routers panics the process on purpose**, so Kubernetes crash-loops it and
someone notices.

### Logging

`--log-level` / `SPITTER_LOG_LEVEL` / `logLevel:` selects `trace` (the binary's default), `debug`, `info` or
`warning`. The rule for new log lines:

- anything that loses or may lose an alert is a `warnf`, with the error in it;
- request headers, payloads, rendered templates, destination responses and template data (which holds the
  environment) are `tracef` only.

The `alerts` package and `dump` still log through `log` directly.

### Tracking upstream's payload

The v4 payload is defined in Alertmanager's `notify/webhook/webhook.go` (`Message`) and `template/template.go`
(`Data`, `Alert`). The version is still `"4"`, but fields get added without a version bump:

- `notification_reason` was added in 0.32 (note the snake_case JSON name);
- `routeLabels` was added in 0.34, already rendered by the dispatcher.

Decoding ignores fields spitter doesn't know, so a new upstream field is silently missing from templates rather
than breaking anything. To expose one:

1. Add it to `AlertmanagerWebhookInputV4` with `json` and `yaml` tags. Without the `json` tag a key that differs
   from the field name decodes to zero without any error.
2. Add it to `AlertmanagerWebhookTemplateV4` and copy it in `Prepare()`.
3. Extend `TestPayloadDecodesEveryField` and the tests next to it in `alerts/webhook_fields_test.go`.

## Decisions already made

These came up in the 2026-11 review and the owner ruled on them. Don't raise them again as findings:

- **The webhook endpoint has no authentication.** It is meant to be reachable by Alertmanager only; the chart's
  opt-in NetworkPolicy enforces that where it can.
- **200 is answered even when sends fail.** Only an unusable payload (not JSON, wrong version) gets a 400.
- **Redirects are followed**, including a 301/302 that turns the POST into a GET.
- **Router documents are fully trusted**: templates can read the environment (`.Env`, sprig's `env`) and
  `tokenFile` can name any readable file.
- **The built-in placeholder router** (no `--config`) stays.
- **Trace logging can hold secrets.** That is what trace is for; the chart runs at `info`.

- **Listener limits** (`httpServer`, `maxBodyBytes`): 10 MiB body (413 beyond it), 10s for headers, 30s for the
  whole request, 10m idle, and deliberately **no write timeout**, because the handler answers only after sending to
  every router. The idle timeout is always set explicitly: left at zero, net/http would reuse the 30s read timeout,
  which is shorter than Alertmanager's 5-minute client idle timeout and would have spitter closing connections
  under it.

## Gotchas when changing code

- **Global state.** `GlobalWebhookServer`, `alerts.GlobalRoutingConfig`, the router mutex, the log level and the
  Prometheus metrics are package globals. `Start()` registers the metrics with the default registry, so it can only
  run once per process. Tests stub the metrics in `TestMain` (`webhook_send_test.go`) and serve `handleWebhooksV4`
  through `startSpitter` (`webhook_handler_test.go`). Do the same rather than calling `Start()`.
- **Routers are immutable once loaded.** Don't add state that changes after `prepare()`; put per-send work in
  `SendWebhook`, as the token file read is.
- **Tests that check log output use `captureLog(t, level)`**, which also restores the level afterwards.
- **HTTPS is verified by default.** Routers need `tls.caFile` (which replaces the system roots, like Prometheus'
  `ca_file`) or `tls.insecureSkipVerify` for self-signed endpoints.
- **YAML is for configuration only**, decoded strictly with `gopkg.in/yaml.v2`. The webhook payload is JSON.
  `yaml.v3` is used by tests only.
- **Listener defaults:** `0.0.0.0:9820`, metrics at `/metrics`, `/healthz` returns `Up`; limits under
  `listen.maxBodyBytes` and `listen.idleTimeout`. `metrics.token` exists
  in the config struct but is **not enforced**.
- **`spitter_webhook_routers` is set once at startup** and does not follow reloads.

## Helm chart (`helm/spitter`)

- Exposure: Service (ClusterIP / NodePort / LoadBalancer), optional Ingress, and Gateway API HTTPRoute.
- Also includes PodMonitor, HPA, PDB and ServiceAccount.
- `spitter.routers` in values is rendered into a generated config, and pods roll when it changes. Routers can also
  be mounted from a ConfigMap/Secret directory and hot-reloaded through the watch interval. `existingConfig` lets
  you bring your own config file.
- `spitter.logLevel` (default `info`) is passed as the `SPITTER_LOG_LEVEL` environment variable, not a flag, so an
  older image still starts.
- `networkPolicy` (**off by default**, the owner's ruling: a selector that misses Alertmanager silently stops every
  alert) admits only Alertmanager and Prometheus pods, selected by prometheus-operator's
  `app.kubernetes.io/name` labels in any namespace. It is rendered only when the callers can be named: in-cluster
  exposure, or `networkPolicy.extraFrom` set when an Ingress, HTTPRoute, NodePort or LoadBalancer is used
  (`spitter.networkPolicy` helper). It is ingress-only; never add an egress rule, which would cut off the
  destinations.
- `values.schema.json` validates values; update it alongside `values.yaml`.
- `ci/*-values.yaml` are lint/test value sets.
- When the app or chart changes, bump `Chart.yaml` `version` (and `appVersion` for app changes). Currently
  version `0.2.3` / appVersion `0.2.2`.

## Container

The `Dockerfile` builds on `$BUILDPLATFORM` and cross-compiles with `GOOS`/`GOARCH` (`CGO_ENABLED=0`, no QEMU). The
runtime image is `gcr.io/distroless/static-debian13:nonroot`: uid 65532, no shell, port 9820, default `router`
command.
