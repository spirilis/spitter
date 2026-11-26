# Review follow-up (branch `alertmanager-v4-new-fields`)

Plan given by the user on 2026-11-25, after the code review. No pushing.

## Fix

- [x] **H1** Parse each router's template at load; reject the router if it does not parse. Isolate routers in the
      handler so a panic in one does not stop the others.
- [x] **H3** Runtime log level (`--log-level`, `SPITTER_LOG_LEVEL`, `logLevel:`). Payloads, headers and template data
      only at trace. Failures at warning. Binary default stays trace; the chart defaults to info.
- [x] **H4** Chart: NetworkPolicy admitting Alertmanager (and Prometheus for scraping) when spitter is only reachable
      in-cluster, or when the user lists the outside sources.
- [x] **M1** Answer 400, not 200, for a payload whose version is not "4".
- [x] **M2** Do not send when filtering leaves no alerts. Recompute `.Status` for a filtered list.
- [x] **M3** Decode the payload as JSON.
- [x] **M4** Nil-safe matching and `Prepare()`; build new label/annotation maps instead of writing into the input.
- [x] **M5** Reload builds fresh router objects (inline routers are cloned) and reloads are serialized.
- [x] **M6** Read `tokenFile` at send time.
- [x] **M8** Strict YAML decoding for the config file and router documents; unparseable router files count as
      rejected; stricter `Check()` (matcher needs a label and a match, URL needs http/https and a host, valid
      method, one auth method only, basic auth with an empty password still sends a header).
- [x] **M11** Examples and READMEs build JSON with `toJson`.
- [x] Tests for each of the above; README, chart README and CLAUDE.md updated.

## Propose only

- [x] **H2** Body limit and server timeouts: write the proposal, do not implement yet.

## Left as is (user's call)

M7 (redirects), M9 (placeholder router), M10 (router documents are trusted), and the always-200 answer for failed
sends (M1, apart from the version check).

## Review

Done on 2026-11-25, as six local commits on `alertmanager-v4-new-fields` (nothing pushed):

1. `Make the log level configurable` (H3)
2. `Decode webhooks as JSON, refuse unknown versions, match whole alerts` (M1, M2, M3, M4)
3. `Validate routers when they are loaded and rebuild them on every reload` (H1, M5, M6, M8)
4. `Build JSON with toJson in the examples` (M11)
5. `Chart: NetworkPolicy for the webhook endpoint, log level defaults to info` (H3, H4)
6. Docs: README and CLAUDE.md

Verified with `go vet`, `go test -race` (coverage of `main` 44% -> 63%), `helm lint` on the three ci value sets,
kubeconform, a server-side dry run of the NetworkPolicy on apollo, and a run of the built binary at info level.
Two fixes were also undone temporarily to confirm their tests fail without them (router cloning, per-router recover).

Choices made along the way, for the owner to confirm:

- ~~The NetworkPolicy is on by default.~~ Reversed by the user: it is off by default (see the follow-up below).
- The binary's default log level stays trace; only the chart defaults to info.
- `.Env` is left out of `{{ . | toJson }}`.
- `AlertmanagerAlertV4` has no `json` tags, so `{{ .Alerts | toJson }}` keeps its key names.
- Chart 0.2.3 / appVersion 0.2.2.

## Follow-up, same day

- [x] NetworkPolicy off by default (user's correction; see `lessons.md`).
- [x] H2 implemented after the user approved the proposal: 10 MiB body limit (413), 10s header and 30s request
      read timeouts, no write timeout, trace body capped at 64 kB.
- [x] Idle timeout: the user asked whether it is appropriate. Kept, set explicitly to 10m and configurable
      (`listen.idleTimeout`, negative for none), because leaving it unset makes net/http use the 30s read timeout,
      below Alertmanager's 5-minute client idle timeout. Awaiting the user's view on the value.
