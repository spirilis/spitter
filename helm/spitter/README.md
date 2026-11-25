# spitter Helm chart

Deploys [spitter](https://github.com/spirilis/spitter), a templating webhook router for Prometheus Alertmanager.
Alertmanager posts to `/v4/alertmanager/webhook`; spitter matches alerts against its routers and re-sends them,
rendered through Go templates (with [sprig](https://masterminds.github.io/sprig/)), to arbitrary HTTP endpoints.

Requires Kubernetes 1.25+.  The HTTPRoute needs the Gateway API CRDs (v1), and the PodMonitor needs the
prometheus-operator CRDs; neither is required unless enabled.

## Install

```sh
helm install spitter ./helm/spitter -n monitoring -f my-values.yaml
```

A minimal `my-values.yaml`:

```yaml
spitter:
  # Links inside alerts are rewritten onto these so they work outside the cluster
  alertmanagerURL: https://alertmanager.example.com
  prometheusURL: https://prometheus.example.com
  routers:
    - url: https://chat.example.com/hooks/alerts
      contentType: application/json
      template: |-
        {"text": {{ printf "[%s] %d alert(s): %s" .Status (len .Alerts) .CommonLabels.alertname | toJson }}}
      matchers:
        - label: severity
          match_re: "critical|warning"
```

Then point an Alertmanager receiver at `http://spitter.monitoring.svc/v4/alertmanager/webhook`
(the release notes print the exact URL).  See [`examples/webhook_server.yml`](../../examples/webhook_server.yml)
for the full router format.

## Exposing spitter

Alertmanager usually runs in the same cluster, so the default `ClusterIP` Service is enough.  To receive webhooks
from outside the cluster, use any combination of the following.  Ingress and HTTPRoute paths default to
`/v4/alertmanager`, keeping `/metrics` and `/healthz` internal.

**NodePort** (or `LoadBalancer`):

```yaml
service:
  type: NodePort
  nodePort: 30820            # optional; omit to let Kubernetes allocate one
  externalTrafficPolicy: Local
```

**Ingress**:

```yaml
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: spitter.example.com
      paths:
        - path: /v4/alertmanager
          pathType: Prefix
  tls:
    - secretName: spitter-tls
      hosts: [spitter.example.com]
```

**Gateway API** (`gateway.networking.k8s.io/v1` HTTPRoute attached to an existing Gateway):

```yaml
httpRoute:
  enabled: true
  parentRefs:
    - name: shared-gateway
      namespace: gateway-system
      sectionName: https     # optional: attach to a single listener
  hostnames:
    - spitter.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /v4/alertmanager
      timeouts:
        request: 30s
```

Rules are passed through as written (matches, filters, timeouts, ...), with `backendRefs` always pointing at the
spitter Service.  When the Gateway lives in another namespace, its listener's `allowedRoutes` must admit this
release's namespace.

## Network policy

spitter's webhook endpoint has no authentication: anyone who can reach it can have alerts sent to your routers'
destinations.  Set `networkPolicy.enabled: true` to have the chart create a NetworkPolicy that only lets
Alertmanager (to post webhooks) and Prometheus (to scrape metrics) connect to the spitter pods.  It is off by
default.  These are its defaults once enabled:

```yaml
networkPolicy:
  enabled: true
  from:
    - namespaceSelector: {}        # any namespace
      podSelector:
        matchLabels:
          app.kubernetes.io/name: alertmanager
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          app.kubernetes.io/name: prometheus
```

Those are the labels prometheus-operator (kube-prometheus-stack) puts on its pods.  **If your Alertmanager's pods
are labelled differently, the policy blocks its webhooks**: check with
`kubectl get pods -A -l app.kubernetes.io/name=alertmanager` before enabling it, and replace `networkPolicy.from`
to match yours.  The default admits a pod with that label in any namespace; put your monitoring namespace in
`namespaceSelector` (`matchLabels: {kubernetes.io/metadata.name: monitoring}`) to narrow it.

An enabled policy can only be created when the callers can be named.  Once spitter is exposed outside the cluster
(Ingress, HTTPRoute, NodePort or LoadBalancer), the traffic arrives from your ingress controller, gateway or an
outside address, which the chart cannot know.  It then creates no policy, and says so in the release notes, unless
`networkPolicy.extraFrom` names those callers:

```yaml
networkPolicy:
  extraFrom:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: ingress-nginx
    # - ipBlock:
    #     cidr: 203.0.113.10/32    # an Alertmanager outside the cluster
```

The policy covers ingress only, so spitter's connections to its destinations are unaffected, and it needs a CNI
that enforces NetworkPolicy.  `networkPolicy.extraIngress` adds whole rules, e.g. for the ports of `extraContainers`.

## Logging

`spitter.logLevel` (default `info`) is passed as `SPITTER_LOG_LEVEL`.  `info` reports startup, reloads and everything
that loses an alert: rejected routers, failed sends and refused payloads.  `trace` adds request headers, alert
payloads, rendered templates and destination responses, which is useful while writing templates but can put secrets
in the log.  Destination URLs appear in warnings at every level.

## Router configuration

There are three ways to provide routers, and they can be combined:

| Source | Values | Change behaviour |
| --- | --- | --- |
| Inline in values | `spitter.routers` | Rendered into a generated ConfigMap (or a Secret with `spitter.configInSecret: true`); pods roll on change. |
| Your own ConfigMap/Secret, one router per key | `spitter.additionalRouters.configMap` / `.secret` | Mounted as a directory and **hot-reloaded** without a restart; spitter polls it every `watchInterval`.  The kubelet takes up to about a minute to sync the edit into the pod. |
| Your own complete config file | `spitter.existingConfig.configMap` / `.secret` + `.key` | Used instead of the generated config.  Set `spitter.port` and `spitter.metricsPath` to match it. |

Routers can hold credentials (`auth.token`, `auth.basicAuth`, `auth.cookies`), so prefer `configInSecret` or a
Secret for `additionalRouters` in that case.  `auth.tokenFile` also works with a Secret mounted via
`extraVolumes`/`extraVolumeMounts`, as does `tls.caFile` for a destination signed by a private CA.  HTTPS
certificates are verified by default; see the [spitter README](../../README.md#router-authentication-and-tls).

## Values

| Key | Default | Description |
| --- | --- | --- |
| `image.registry` / `image.repository` | `docker.io` / `spirilis/spitter` | Image location. |
| `image.tag` | chart `appVersion` | Image tag. |
| `image.digest` | `""` | Pin by digest; wins over `tag`. |
| `spitter.port` | `9820` | Container listen port. |
| `spitter.alertmanagerURL` / `spitter.prometheusURL` | `""` | External base URLs used to rewrite alert links.  Required unless `existingConfig` is set. |
| `spitter.logLevel` | `info` | `trace`, `debug`, `info` or `warning`; `""` leaves it to the config file or spitter's default (`trace`). |
| `spitter.maxBodyBytes` | `0` (spitter's 10 MiB) | Largest webhook body accepted; larger ones get a 413. |
| `spitter.idleTimeout` | `""` (spitter's `10m`) | How long an idle keep-alive connection is kept; keep it above your ingress proxy's. |
| `spitter.metricsPath` | `/metrics` | Metrics path (also used by the PodMonitor). |
| `spitter.routers` | `[]` | Inline routers. |
| `spitter.configInSecret` | `false` | Store the generated config in a Secret. |
| `spitter.existingConfig.*` | unset | Use an existing ConfigMap/Secret key as the config file. |
| `spitter.additionalRouters.*` | unset | Hot-reloaded router directory from a ConfigMap/Secret. |
| `spitter.additionalRouters.watchInterval` | `10s` | Poll interval; `0s` disables hot reload. |
| `spitter.extraArgs` | `[]` | Extra `spitter router` arguments. |
| `service.type` | `ClusterIP` | `ClusterIP`, `NodePort` or `LoadBalancer`. |
| `service.port` | `80` | Service port. |
| `service.nodePort` | `null` | Fixed node port for NodePort/LoadBalancer. |
| `service.externalTrafficPolicy` | `""` | `Cluster` or `Local` for NodePort/LoadBalancer. |
| `service.loadBalancerClass` / `service.loadBalancerSourceRanges` | unset | LoadBalancer options. |
| `service.extraPorts` | `[]` | Additional ServicePorts, e.g. for sidecars. |
| `ingress.*` | disabled | `networking.k8s.io/v1` Ingress. |
| `httpRoute.*` | disabled | Gateway API HTTPRoute. |
| `networkPolicy.enabled` | `false` | NetworkPolicy admitting only the peers below; skipped when spitter is exposed externally and `extraFrom` is empty. |
| `networkPolicy.from` | Alertmanager and Prometheus pods in any namespace | Peers allowed to reach spitter's port. |
| `networkPolicy.extraFrom` / `networkPolicy.extraIngress` | `[]` | More peers for spitter's port / more ingress rules. |
| `metrics.podMonitor.*` | disabled | prometheus-operator PodMonitor (`labels`, `interval`, `relabelings`, ...). |
| `autoscaling.*` | disabled | HorizontalPodAutoscaler (`autoscaling/v2`). |
| `podDisruptionBudget.*` | disabled | PodDisruptionBudget. |
| `serviceAccount.automount` | `false` | spitter does not use the Kubernetes API. |
| `podSecurityContext` / `securityContext` | non-root 65532, read-only root FS, all capabilities dropped | Compatible with the `restricted` Pod Security Standard. |
| `env` / `envFrom` | `[]` | Plain `EnvVar` / `EnvFromSource` lists. |
| `extraVolumes` / `extraVolumeMounts` / `initContainers` / `extraContainers` | `[]` | Pass-through pod spec additions. |

See [`values.yaml`](values.yaml) for everything else (probes, lifecycle hooks, resources, scheduling).

## Upgrading from 0.1.x

0.2.0 is a rewrite and the values layout changed:

- The image is now distroless and has no shell.  The `config-reload.sh` sidecar and reload-trigger emptyDir are gone;
  spitter watches the `additionalRouters` directory itself.
- `spitter.router.config.*` became `spitter.existingConfig.*` (or the generated config); `spitter.router.routers`
  became `spitter.routers`; `spitter.router.additionalRouters.configMap` became `spitter.additionalRouters.configMap`.
- `service.nodePort.enabled/number` became `service.type: NodePort` plus `service.nodePort`.
- `prometheus.*` became `metrics.podMonitor.*`.  The extra `spitter-prometheus` selector label is gone; if 0.1.x ran
  with `prometheus.enabled: true`, the Deployment selector changes, so uninstall that release before installing 0.2.0.
- `env` and `envFrom` are now plain Kubernetes lists.
