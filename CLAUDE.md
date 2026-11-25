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
helm lint helm/spitter -f helm/spitter/ci/<x>-values.yaml   # clusterip, gateway, nodeport-ingress
docker buildx build --platform linux/amd64,linux/arm64 -t spirilis/spitter:<ver> .
```

The binary has two kong subcommands (`main.go`):

- `spitter router` (the image's default CMD) runs the router. It takes `--config`, `--alertmanager`,
  `--prometheus`, `--routers`, `--routers-watch-interval` and `--reload-trigger`, each with a `SPITTER_*`
  environment variable. A flag or variable overrides the config file. With no `--config` at all, a built-in
  placeholder config is used, which is only useful for smoke testing.
- `spitter dump [--listen] [--port]` (`dump/`) runs a tiny server that prints every request to stdout. Point a
  router at it while developing templates.

## Layout

| Path | What it holds |
| --- | --- |
| `main.go` | CLI parsing, config file load (YAML), CLI overrides, then `WebhookServer.Start()`. Also the `DEBUGLEVEL_*` constants (all `true`, so trace logging is always on). |
| `webhook_server.go` | Almost all the logic: `WebhookRouter` (+ `WebhookAuthentication`, `WebhookTLS`), `WebhookMatcher`, `WebhookServer` (config, reload, watchers, metrics, HTTP handlers). |
| `alerts/alertmanager.go` | Alertmanager v4 payload types, `Prepare()` → template data, and `URLReplacements` (link rewriting). Holds `GlobalRoutingConfig`. |
| `dump/` | The `dump` subcommand. |
| `examples/webhook_server.yml` | Reference config showing every router option. `examples/*_local.yml` is gitignored for personal configs. |
| `helm/spitter/` | Helm chart (see below). |
| `PROMETHEUS-METRICS.md` | Metric list. The `WebhookServer` section is implemented; the per-alert/per-label section is still only a proposal. |
| `*_test.go` | Routing/filtering, matcher validation, send status handling, auth/TLS, router-dir checksum (`router_watch_test.go`), templates and URL rewriting (`alerts/templates_test.go`). |

## Request flow

1. `handleWebhooksV4` accepts POST only. It decodes the body with the **YAML** decoder (JSON is valid YAML) into
   `alerts.AlertmanagerWebhookInputV4`.
2. For each router from `GlobalWebhookServer.GetRouters()`, the router is a candidate only when **every** matcher
   matches something: `CommonLabels` or any alert's labels (`HasMatchingAlerts`).
3. `PrepareTemplateData` calls `Prepare()`, which:
   - rejects anything but version `"4"`;
   - copies common labels and annotations into each alert;
   - rewrites `ExternalURL` and `GeneratorURL` onto the configured bases (the originals stay in
     `OriginalExternalURL` and `OriginalGeneratorURL`);
   - exposes the process environment as `.Env`.

   If the common labels don't satisfy every matcher, alerts that don't individually satisfy all of them are
   **dropped** from `.Alerts` (`IsMatchingAlert`).
4. `SendWebhook` renders the template and sends it with the router's method (default `POST`) and content type
   (default `application/yaml`). It adds the `Authorization` header (bearer token, token file or basic auth) and any
   cookies, and uses a per-router `http.Client` (30s timeout, TLS settings). Only a 2xx response counts as success.
5. Routers run **sequentially**, and the handler always answers 200 to Alertmanager. Send errors are only logged
   and reflected in the metrics.

Template data is `alerts.AlertmanagerWebhookTemplateV4` (field table in README "Template data"). It has
`.Status`, `.Receiver`, `.GroupLabels`, `.CommonLabels`, `.CommonAnnotations`, `.RouteLabels`,
`.NotificationReason`, `.ExternalURL`, `.OriginalExternalURL` and `.Env`. Its `.Alerts` each have
`.Status`, `.Labels`, `.Annotations`, `.StartsAt`, `.EndsAt`, `.GeneratorURL`, `.OriginalGeneratorURL` and
`.Fingerprint`.

### Matchers

`{label, match}` is an exact match and `{label, match_re}` is a Go regexp. A regexp is unanchored, so `"crit"`
matches `"critical"`. If both are set, either one may match. The regexp is compiled in `Check()`, so a bad
`match_re` rejects the router at load time.

### Router loading and reload

`ReloadRouters()` builds the router list from two sources:

- the inline `routers:` in the config file;
- every file in `addlRouterDir`, one router document per file (YAML or JSON).

Each router goes through `Check()` (URL, template and ≥1 matcher; compiles the regexps) and then `prepare()`
(defaults, token file, HTTP client). Invalid routers are counted in `spitter_webhook_routers_rejected` and skipped.
Files that don't parse are skipped silently and are not counted. If no valid routers remain, reload returns an
error.

Reload is triggered by:

- `SIGHUP`;
- the `reloadTriggerFile` appearing (polled every 5s, then deleted);
- a change in the `addlRouterDir` content checksum, when `addlRouterDirWatchInterval` / `--routers-watch-interval`
  is greater than 0. The checksum follows symlinks, so a Kubernetes ConfigMap `..data` swap counts as a change.

**A reload that ends with zero valid routers panics the process on purpose**, so Kubernetes crash-loops it and
someone notices.

### Tracking upstream's payload

The v4 payload is defined in Alertmanager's `notify/webhook/webhook.go` (`Message`) and `template/template.go`
(`Data`, `Alert`). The version is still `"4"`, but fields get added without a version bump:

- `notification_reason` was added in 0.32 (note the snake_case JSON name);
- `routeLabels` was added in 0.34, already rendered by the dispatcher.

Decoding ignores fields spitter doesn't know, so a new upstream field is silently missing from templates rather
than breaking anything. To expose one, add it to both `AlertmanagerWebhookInputV4` and
`AlertmanagerWebhookTemplateV4`, copy it in `Prepare()`, and extend `alerts/webhook_fields_test.go`.

## Gotchas when changing code

- **Global state.** `GlobalWebhookServer`, `alerts.GlobalRoutingConfig`, the router mutex, and the Prometheus
  metrics are package globals. `Start()` registers the metrics with the default registry, so it can only run once
  per process. Tests call `Check()`/`prepare()`/`SendWebhook()` directly and stub
  `webhookreqSuccessfulCounter` in `TestMain` (`webhook_send_test.go`). Do the same rather than calling `Start()`.
- **Templates are only parsed at send time.** `SendWebhook` uses `template.Must` on every call, so a
  syntactically bad template passes `Check()` and panics inside the handler (net/http recovers it, and the
  remaining routers for that request are skipped).
- **Inline routers are re-prepared on every reload while requests may be using them**, which is why `client` is
  an `atomic.Pointer`. Keep that in mind before adding more mutable router state.
- **`Prepare()` writes common labels/annotations into the incoming alert's own maps** using `maps.Copy`, with no
  nil check on the destination.
- **The `alerts` package logs via `log`; `main` gates its logging on the `DEBUGLEVEL_*` constants.** There is no
  runtime log-level control (it's a TODO). Trace logging dumps full payloads and rendered templates.
- **HTTPS is verified by default** (a change since earlier versions). Routers need `tls.caFile` (which replaces the
  system roots, like Prometheus' `ca_file`) or `tls.insecureSkipVerify` for self-signed endpoints. An unreadable
  `caFile` or `tokenFile` rejects the router.
- **Two YAML libraries are in `go.mod`:** `gopkg.in/yaml.v2` is used for the config file and payload decoding.
  Struct tags are `yaml:"..."`.
- **Listener defaults:** `0.0.0.0:9820`, metrics at `/metrics`, `/healthz` returns `Up`. `metrics.token` exists
  in the config struct but is **not enforced**.

## Helm chart (`helm/spitter`)

- Exposure: Service (ClusterIP / NodePort / LoadBalancer), optional Ingress, and Gateway API HTTPRoute.
- Also includes PodMonitor, HPA, PDB and ServiceAccount.
- `spitter.routers` in values is rendered into a generated config, and pods roll when it changes. Routers can also
  be mounted from a ConfigMap/Secret directory and hot-reloaded through the watch interval. `existingConfig` lets
  you bring your own config file.
- `values.schema.json` validates values; update it alongside `values.yaml`.
- `ci/*-values.yaml` are lint/test value sets.
- When the app or chart changes, bump `Chart.yaml` `version` (and `appVersion` for app changes). Currently
  version `0.2.2` / appVersion `0.2.1`.

## Container

The `Dockerfile` builds on `$BUILDPLATFORM` and cross-compiles with `GOOS`/`GOARCH` (`CGO_ENABLED=0`, no QEMU). The
runtime image is `gcr.io/distroless/static-debian13:nonroot`: uid 65532, no shell, port 9820, default `router`
command.
