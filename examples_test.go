package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/spirilis/spitter/alerts"
)

// Text an alert's author controls, written to break out of a JSON string
var hostileAnnotations = map[string]string{
	"summary":     `disk "full" on C:\ </script>`,
	"description": `", "injected": "yes`,
	"multi\"line": "first\nsecond\ttabbed",
}

func hostilePayload() *alerts.AlertmanagerWebhookInputV4 {
	return &alerts.AlertmanagerWebhookInputV4{
		Version:           "4",
		Status:            `firing", "injected": "yes`,
		ExternalURL:       `http://alertmanager:9093/"quoted"`,
		CommonLabels:      map[string]string{"severity": "critical", "alertname": `Disk"Full`},
		CommonAnnotations: map[string]string{},
		Alerts: []*alerts.AlertmanagerAlertV4{
			{Status: "firing", Labels: map[string]string{"instance": `host"1`}, Annotations: hostileAnnotations, GeneratorURL: "http://prometheus:9090/graph?g0.expr=up"},
			{Status: "resolved", Labels: map[string]string{"instance": "host2"}, Annotations: map[string]string{}},
		},
	}
}

// renderJSON runs a router's template over the hostile payload and returns the decoded result
func renderJSON(t *testing.T, r *WebhookRouter) map[string]any {
	t.Helper()
	data, err := r.PrepareTemplateData(hostilePayload())
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.tmpl.Execute(&b, data); err != nil {
		t.Fatalf("executing template: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b.Bytes(), &out); err != nil {
		t.Fatalf("template output is not valid JSON: %v\n%s", err, b.String())
	}
	if _, found := out["injected"]; found {
		t.Errorf("alert text added a field of its own to the payload:\n%s", b.String())
	}
	return out
}

// The example config is what people copy: it has to load, and its JSON templates have to survive hostile alert text
func TestExampleConfig(t *testing.T) {
	captureLog(t, "warning")
	initRoutingConfig(t)
	cfg, err := loadConfigFile("examples/webhook_server.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routers) != 3 {
		t.Fatalf("example config has %d routers, want 3", len(cfg.Routers))
	}
	jsonRouters := 0
	for i, r := range cfg.Routers {
		if err := r.Check(); err != nil {
			t.Fatalf("router %d is rejected: %v", i+1, err)
		}
		if r.ContentType != "application/json" {
			continue
		}
		jsonRouters++
		out := renderJSON(t, r)

		list, ok := out["Alerts"].([]any)
		if !ok {
			continue // the router that only reports a count
		}
		if len(list) != 2 {
			t.Fatalf("router %d rendered %d alerts, want 2", i+1, len(list))
		}
		got := map[string]string{}
		for k, v := range list[0].(map[string]any)["Annotations"].(map[string]any) {
			got[k] = v.(string)
		}
		if !reflect.DeepEqual(got, hostileAnnotations) {
			t.Errorf("router %d: annotations did not survive the template\n got %q\nwant %q", i+1, got, hostileAnnotations)
		}
	}
	if jsonRouters != 2 {
		t.Errorf("checked %d JSON routers in the example config, want 2", jsonRouters)
	}
}

// The one-line examples in the chart's README, values.yaml and ci values
func TestDocumentedJSONTemplates(t *testing.T) {
	captureLog(t, "warning")
	initRoutingConfig(t)
	for name, tmpl := range map[string]string{
		"chart README": `{"text": {{ printf "[%s] %d alert(s): %s" .Status (len .Alerts) .CommonLabels.alertname | toJson }}}`,
		"chart values": `{"status": {{ .Status | toJson }}, "alerts": {{ len .Alerts }}}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := &WebhookRouter{DestURL: "http://receiver.example.com/hook", Template: tmpl, Matchers: []*WebhookMatcher{{Label: "severity", MatchString: "critical"}}}
			if err := r.Check(); err != nil {
				t.Fatal(err)
			}
			renderJSON(t, r)
		})
	}
}

// What toJson prints for the template data is something existing templates depend on
func TestToJsonOfTemplateData(t *testing.T) {
	captureLog(t, "warning")
	initRoutingConfig(t)
	t.Setenv("SPITTER_TEST_SECRET", "env-secret-value")
	render := func(tmpl string) string {
		t.Helper()
		r := &WebhookRouter{DestURL: "http://receiver.example.com/hook", Template: tmpl, Matchers: []*WebhookMatcher{{Label: "severity", MatchString: "critical"}}}
		if err := r.Check(); err != nil {
			t.Fatal(err)
		}
		data, err := r.PrepareTemplateData(hostilePayload())
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		if err := r.tmpl.Execute(&b, data); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	// The whole payload as JSON must not carry the process environment along
	whole := render(`{{ . | toJson }}`)
	if strings.Contains(whole, "env-secret-value") {
		t.Errorf("{{ . | toJson }} includes the environment")
	}
	if !json.Valid([]byte(whole)) {
		t.Errorf("{{ . | toJson }} is not valid JSON")
	}
	if got := render(`{{ .Env.SPITTER_TEST_SECRET }}`); got != "env-secret-value" {
		t.Errorf(".Env.SPITTER_TEST_SECRET rendered %q, want the variable's value", got)
	}

	// Alerts keep the key names they have always been printed with
	var alertList []map[string]any
	if err := json.Unmarshal([]byte(render(`{{ .Alerts | toJson }}`)), &alertList); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Status", "Labels", "Annotations", "StartsAt", "EndsAt", "GeneratorURL", "OriginalGeneratorURL", "Fingerprint"} {
		if _, found := alertList[0][key]; !found {
			t.Errorf("{{ .Alerts | toJson }} has no %q key: %v", key, alertList[0])
		}
	}
}
