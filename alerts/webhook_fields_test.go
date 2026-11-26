package alerts

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
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
	if err := json.Unmarshal([]byte(payload), in); err != nil {
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

// Every key Alertmanager sends must land in its field: encoding/json drops the ones it cannot place without a word
func TestPayloadDecodesEveryField(t *testing.T) {
	in := new(AlertmanagerWebhookInputV4)
	if err := json.Unmarshal([]byte(upstreamV4Payload), in); err != nil {
		t.Fatal(err)
	}
	want := &AlertmanagerWebhookInputV4{
		Version:            "4",
		GroupKey:           `{}:{alertname="Watchdog"}`,
		Status:             "firing",
		Receiver:           "spitter",
		GroupLabels:        map[string]string{"alertname": "Watchdog"},
		CommonLabels:       map[string]string{"alertname": "Watchdog", "severity": "none"},
		CommonAnnotations:  map[string]string{},
		RouteLabels:        map[string]string{"team": "platform", "pager": "secondary"},
		ExternalURL:        "http://alertmanager:9093",
		NotificationReason: "new alerts added",
		Alerts: []*AlertmanagerAlertV4{{
			Status:       "firing",
			Labels:       map[string]string{"alertname": "Watchdog", "severity": "none"},
			Annotations:  map[string]string{},
			StartsAt:     "2026-11-25T10:00:00Z",
			EndsAt:       "0001-01-01T00:00:00Z",
			GeneratorURL: "http://prometheus:9090/graph?g0.expr=vector%281%29",
			Fingerprint:  "e2a5a3cab1d0c6b1",
		}},
	}
	if !reflect.DeepEqual(in, want) {
		t.Errorf("decoded\n%#v\nalert %#v\nwant\n%#v\nalert %#v", in, in.Alerts[0], want, want.Alerts[0])
	}

	in = new(AlertmanagerWebhookInputV4)
	if err := json.Unmarshal([]byte(`{"version": "4", "truncatedAlerts": 7}`), in); err != nil {
		t.Fatal(err)
	}
	if in.TruncatedAlertCount != 7 {
		t.Errorf("TruncatedAlertCount = %d, want 7", in.TruncatedAlertCount)
	}
}

// Prepare runs once per matching router on the same payload, so it must neither change it nor trip over what is missing
func TestPrepareLeavesPayloadUntouched(t *testing.T) {
	if err := ParseRoutingConfigs("https://am.example.com", "https://prom.example.com", ""); err != nil {
		t.Fatal(err)
	}
	in := &AlertmanagerWebhookInputV4{
		Version:           "4",
		CommonLabels:      map[string]string{"severity": "critical"},
		CommonAnnotations: map[string]string{"runbook": "rb"},
		Alerts: []*AlertmanagerAlertV4{
			{Labels: map[string]string{"alertname": "A"}, Annotations: map[string]string{"summary": "s"}},
			nil,
			{}, // no labels or annotations at all
		},
	}

	for range 2 {
		out, err := in.Prepare()
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Alerts) != 2 {
			t.Fatalf("Prepare kept %d alerts, want 2 (the nil one dropped)", len(out.Alerts))
		}
		wantLabels := []map[string]string{{"alertname": "A", "severity": "critical"}, {"severity": "critical"}}
		wantAnnotations := []map[string]string{{"summary": "s", "runbook": "rb"}, {"runbook": "rb"}}
		for i, al := range out.Alerts {
			if !reflect.DeepEqual(al.Labels, wantLabels[i]) {
				t.Errorf("alert %d labels = %v, want %v", i, al.Labels, wantLabels[i])
			}
			if !reflect.DeepEqual(al.Annotations, wantAnnotations[i]) {
				t.Errorf("alert %d annotations = %v, want %v", i, al.Annotations, wantAnnotations[i])
			}
		}
	}
	if got := in.Alerts[0].Labels; !reflect.DeepEqual(got, map[string]string{"alertname": "A"}) {
		t.Errorf("Prepare changed the payload's own labels to %v", got)
	}
	if in.Alerts[2].Labels != nil || in.Alerts[2].Annotations != nil {
		t.Errorf("Prepare filled in the payload's missing maps")
	}
}
