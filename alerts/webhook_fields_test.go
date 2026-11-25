package alerts

import (
	"bytes"
	"testing"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v2"
)

// A v4 payload as Alertmanager 0.34+ sends it: notification_reason (0.32+) and routeLabels (0.34+) alongside the original fields
var upstreamV4Payload = `{
  "version": "4",
  "groupKey": "{}:{alertname=\"Watchdog\"}",
  "truncatedAlerts": 0,
  "status": "firing",
  "receiver": "spitter",
  "groupLabels": {"alertname": "Watchdog"},
  "commonLabels": {"alertname": "Watchdog", "severity": "none"},
  "commonAnnotations": {},
  "routeLabels": {"team": "platform", "pager": "secondary"},
  "externalURL": "http://alertmanager:9093",
  "notification_reason": "new alerts added",
  "alerts": [
    {
      "status": "firing",
      "labels": {"alertname": "Watchdog", "severity": "none"},
      "annotations": {},
      "startsAt": "2026-11-25T10:00:00Z",
      "endsAt": "0001-01-01T00:00:00Z",
      "generatorURL": "http://prometheus:9090/graph?g0.expr=vector%281%29",
      "fingerprint": "e2a5a3cab1d0c6b1"
    }
  ]
}`

func prepareUpstreamPayload(t *testing.T, payload string) *AlertmanagerWebhookTemplateV4 {
	t.Helper()
	// Decode the way handleWebhooksV4 does
	in := new(AlertmanagerWebhookInputV4)
	if err := yaml.NewDecoder(bytes.NewBufferString(payload)).Decode(in); err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	if err := ParseRoutingConfigs("https://am.example.com", "https://prom.example.com", ""); err != nil {
		t.Fatal(err)
	}
	out, err := in.Prepare()
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return out
}

func TestNotificationReasonAndRouteLabels(t *testing.T) {
	data := prepareUpstreamPayload(t, upstreamV4Payload)

	tp := template.Must(template.New("t").Funcs(sprig.FuncMap()).Parse(
		`{{ .NotificationReason }}|{{ .RouteLabels.team }}|{{ index .RouteLabels "pager" }}`))
	var b bytes.Buffer
	if err := tp.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	if got, want := b.String(), "new alerts added|platform|secondary"; got != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}

func TestOlderPayloadWithoutNewFields(t *testing.T) {
	// Alertmanager before 0.32 sends neither field; templates must still render rather than fail
	data := prepareUpstreamPayload(t, `{"version": "4", "status": "resolved", "alerts": []}`)

	tp := template.Must(template.New("t").Funcs(sprig.FuncMap()).Parse(
		`[{{ .NotificationReason }}]{{ if .RouteLabels.team }}team{{ end }}{{ len .RouteLabels }}`))
	var b bytes.Buffer
	if err := tp.Execute(&b, data); err != nil {
		t.Fatal(err)
	}
	if got, want := b.String(), "[]0"; got != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}
