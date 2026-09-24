package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/spirilis/spitter/alerts"
	"gopkg.in/yaml.v3"
)

// Webhook routing is in webhook_server.go FYI

// Note I'm using the YAML decoder library here since JSON is valid YAML, I can use YAML in my tests.
var exampleRouterConfig1 = `
url: https://our-company.service-now.com/v1/webhook
method: POST
matchers:
  - label: severity
    match: error
  - label: application
    match_re: ".*our-company.*"
template: |-
  status: {{ .Status }}
  alerts: {{ .Alerts | len }}
  runbook summaries:
  {{- range .Alerts }}
    {{- if .Annotations.runbook_summary }}
    {{ .Annotations.runbook_summary }}
    {{- end }}
  {{- end }}
`

var exampleAlerts1 = `
version: "4"
groupKey: asdf
truncatedAlerts: 0
status: firing
receiver: fdsa
groupLabels:
  job: test1
  prometheus: rancher-monitoring-prometheus
commonLabels:
  myalert: "true"
commonAnnotations:
  summary: These are test alerts
externalURL: http://rancher-monitoring-alertmanager.cattle-monitoring-system:9093/alerts
alerts:
  - fingerprint: fdsa
    status: firing
    generatorURL: http://rancher-monitoring-prometheus.cattle-monitoring-system:9090/graph?g0.expr=kube_pod_info%7Bnamespace%3D\"kube-system\"%2Cpod%3D~\"aws-node-.*\"%7D&g0.tab=1&g0.stacked=0&g0.show_exemplars=0&g0.range_input=1h
    startsAt: asdf
    endsAt: fdsa
    annotations:
      runbook_summary: This is only a test
    labels:
      namespace: kube-system
      pod: aws-node-abcde
      severity: error
      application: "eks-cni-for-our-company"
  - fingerprint: uiop
    status: firing
    generatorURL: http://rancher-monitoring-prometheus.cattle-monitoring-system:9090/graph?g0.expr=kube_pod_info%7Bnamespace%3D\"my-tenant\"%2Cpod%3D~\"company-app-.*\"%7D&g0.tab=1&g0.stacked=0&g0.show_exemplars=0&g0.range_input=1h
    startsAt: asdf
    endsAt: fdsa
    annotations:
      runbook_summary: This is a test alert from another tenant in our cluster
    labels:
      namespace: my-tenant
      pod: company-app-xyz
      severity: info
      application: "app-for-another-company"
`

// PrepareTemplateData refuses to run until the URL transmutation config is initialized
func initRoutingConfig(t *testing.T) {
	t.Helper()
	if err := alerts.ParseRoutingConfigs("http://alertmanager.example.com", "http://prometheus.example.com", ""); err != nil {
		t.Fatalf("Error initializing routing config: %v", err)
	}
}

// fingerprints lists the alerts' fingerprints in order, so a test can check which alerts a router kept
func fingerprints(al []*alerts.AlertmanagerAlertV4) []string {
	var out []string
	for _, a := range al {
		out = append(out, a.Fingerprint)
	}
	return out
}

func TestExampleAlertRouting1(t *testing.T) {
	initRoutingConfig(t)

	webhook_router_yaml := bytes.NewBuffer([]byte(exampleRouterConfig1))
	dec := yaml.NewDecoder(webhook_router_yaml)
	webhook_router := new(WebhookRouter)
	err := dec.Decode(webhook_router)
	if err != nil {
		t.Fatalf("Error decoding WebhookRouter object: %v", err)
	}
	if webhook_router.DestURL != "https://our-company.service-now.com/v1/webhook" {
		t.Errorf("DestURL = %q, want https://our-company.service-now.com/v1/webhook", webhook_router.DestURL)
	}
	if webhook_router.HttpMethod != "POST" {
		t.Errorf("HttpMethod = %q, want POST", webhook_router.HttpMethod)
	}
	if len(webhook_router.Matchers) != 2 {
		t.Fatalf("decoded %d matchers, want 2", len(webhook_router.Matchers))
	}

	alert_yaml := bytes.NewBuffer([]byte(exampleAlerts1))
	dec = yaml.NewDecoder(alert_yaml)
	alert := new(alerts.AlertmanagerWebhookInputV4)
	err = dec.Decode(alert)
	if err != nil {
		t.Fatalf("Error decoding AlertmanagerWebhookInputV4 object: %v", err)
	}
	if len(alert.Alerts) != 2 {
		t.Fatalf("decoded %d alerts, want 2", len(alert.Alerts))
	}

	templated, err := webhook_router.PrepareTemplateData(alert)
	if err != nil {
		t.Fatalf("PrepareTemplateData error: %v", err)
	}
	// commonLabels satisfy neither matcher, so only fdsa (severity=error, application=eks-cni-for-our-company) may be routed;
	// uiop belongs to another tenant and must be dropped.
	if got := fingerprints(templated.Alerts); fmt.Sprint(got) != "[fdsa]" {
		t.Errorf("PrepareTemplateData kept alerts %v, want [fdsa]", got)
	}
}

func TestPrepareTemplateDataFiltering(t *testing.T) {
	initRoutingConfig(t)

	// Same matchers as exampleRouterConfig1
	ourCompanyMatchers := func() []*WebhookMatcher {
		return []*WebhookMatcher{
			{Label: "severity", MatchString: "error"},
			{Label: "application", MatchRegexp: ".*our-company.*"},
		}
	}
	newAlert := func(fingerprint string, labels map[string]string) *alerts.AlertmanagerAlertV4 {
		return &alerts.AlertmanagerAlertV4{Status: "firing", Fingerprint: fingerprint, Labels: labels}
	}

	// Alertmanager repeats commonLabels in every alert's labels; Prepare() merges them in, so the alerts below leave them out.
	tests := []struct {
		name         string
		matchers     []*WebhookMatcher
		commonLabels map[string]string
		alertList    []*alerts.AlertmanagerAlertV4
		want         []string // fingerprints of the alerts the router should keep
	}{
		{
			name:         "all matchers satisfied by commonLabels keeps every alert",
			matchers:     ourCompanyMatchers(),
			commonLabels: map[string]string{"severity": "error", "application": "eks-cni-for-our-company"},
			alertList: []*alerts.AlertmanagerAlertV4{
				newAlert("a", map[string]string{"pod": "aws-node-abcde"}),
				newAlert("b", map[string]string{"pod": "aws-node-fghij"}),
			},
			want: []string{"a", "b"},
		},
		{
			name:         "partial commonLabels match is completed by per-alert labels",
			matchers:     ourCompanyMatchers(),
			commonLabels: map[string]string{"severity": "error"},
			alertList: []*alerts.AlertmanagerAlertV4{
				newAlert("ours", map[string]string{"application": "eks-cni-for-our-company"}),
				newAlert("theirs", map[string]string{"application": "app-for-another-company"}),
				newAlert("no-application", map[string]string{"pod": "aws-node-abcde"}),
			},
			want: []string{"ours"},
		},
		{
			name:         "no commonLabels match keeps only alerts that satisfy every matcher themselves",
			matchers:     ourCompanyMatchers(),
			commonLabels: map[string]string{"myalert": "true"},
			alertList: []*alerts.AlertmanagerAlertV4{
				newAlert("both", map[string]string{"severity": "error", "application": "eks-cni-for-our-company"}),
				newAlert("severity-only", map[string]string{"severity": "error", "application": "app-for-another-company"}),
				newAlert("application-only", map[string]string{"severity": "info", "application": "eks-cni-for-our-company"}),
				newAlert("neither", map[string]string{"severity": "info", "application": "app-for-another-company"}),
			},
			want: []string{"both"},
		},
		{
			name: "matchers on the same label must each be satisfied",
			matchers: []*WebhookMatcher{
				{Label: "application", MatchRegexp: ".*our-company.*"},
				{Label: "application", MatchRegexp: "^eks-"},
			},
			commonLabels: map[string]string{"application": "app-for-our-company"},
			alertList: []*alerts.AlertmanagerAlertV4{
				newAlert("a", map[string]string{"pod": "company-app-xyz"}),
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &WebhookRouter{Matchers: tc.matchers}
			in := &alerts.AlertmanagerWebhookInputV4{
				Version:      "4",
				Status:       "firing",
				CommonLabels: tc.commonLabels,
				Alerts:       tc.alertList,
			}
			templated, err := r.PrepareTemplateData(in)
			if err != nil {
				t.Fatalf("PrepareTemplateData error: %v", err)
			}
			if got := fingerprints(templated.Alerts); fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("PrepareTemplateData kept alerts %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRouterCheckMatchers(t *testing.T) {
	tests := []struct {
		name     string
		matchers []*WebhookMatcher
		wantErr  bool
	}{
		{
			name:     "valid match and match_re",
			matchers: []*WebhookMatcher{{Label: "severity", MatchString: "error"}, {Label: "application", MatchRegexp: ".*our-company.*"}},
		},
		{
			name:     "invalid match_re",
			matchers: []*WebhookMatcher{{Label: "severity", MatchString: "error"}, {Label: "application", MatchRegexp: "our-(company"}},
			wantErr:  true,
		},
		{
			name:     "nil matcher",
			matchers: []*WebhookMatcher{nil},
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &WebhookRouter{DestURL: "http://destination/webhook", Template: "{{ .Status }}", Matchers: tc.matchers}
			if err := r.Check(); (err != nil) != tc.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// A matcher that never went through Check() (e.g. built directly) must not panic on a bad match_re
func TestInvalidMatchRegexpDoesNotMatch(t *testing.T) {
	m := &WebhookMatcher{Label: "severity", MatchRegexp: "err(or"}
	if m.IsMatch("severity", "error") {
		t.Errorf("IsMatch with invalid match_re returned true, want false")
	}
	a := &alerts.AlertmanagerWebhookInputV4{
		Version:      "4",
		CommonLabels: map[string]string{"severity": "error"},
		Alerts:       []*alerts.AlertmanagerAlertV4{{Labels: map[string]string{"severity": "error"}}},
	}
	if m.HasMatchingAlerts(a) {
		t.Errorf("HasMatchingAlerts with invalid match_re returned true, want false")
	}
}

func TestReloadRoutersRejectsInvalidMatchRegexp(t *testing.T) {
	routerYAML := func(url, matchRegexp string) string {
		return fmt.Sprintf("url: %s\ntemplate: \"{{ .Status }}\"\nmatchers:\n  - label: severity\n    match_re: %q\n", url, matchRegexp)
	}
	decodeRouter := func(y string) *WebhookRouter {
		r := new(WebhookRouter)
		if err := yaml.NewDecoder(bytes.NewBufferString(y)).Decode(r); err != nil {
			t.Fatalf("Error decoding WebhookRouter object: %v", err)
		}
		return r
	}

	// Cover both places routers come from: the main config and the additional router directory
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"bad.yml":  routerYAML("http://bad-dir", "err(or"),
		"good.yml": routerYAML("http://good-dir", "err.*"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatalf("Error writing router file: %v", err)
		}
	}
	w := &WebhookServer{
		Routers: []*WebhookRouter{
			decodeRouter(routerYAML("http://good-inline", "err.*")),
			decodeRouter(routerYAML("http://bad-inline", "err(or")),
		},
		AdditionalRouterDirectory: dir,
	}

	if err := w.ReloadRouters(); err != nil {
		t.Fatalf("ReloadRouters error: %v", err)
	}
	var urls []string
	for _, r := range w.GetRouters() {
		urls = append(urls, r.DestURL)
	}
	if fmt.Sprint(urls) != "[http://good-inline http://good-dir]" {
		t.Errorf("ReloadRouters kept routers %v, want [http://good-inline http://good-dir]", urls)
	}
	if routersRejected != 2 {
		t.Errorf("routersRejected = %d, want 2", routersRejected)
	}
}

func TestSendWebhookStatusHandling(t *testing.T) {
	// Each case gets a fresh copy of the counter TestMain installs, so it can check this one send's effect on it
	savedCounter := webhookreqSuccessfulCounter
	t.Cleanup(func() { webhookreqSuccessfulCounter = savedCounter })

	tests := []struct {
		status  int
		wantErr bool
	}{
		{status: http.StatusOK},
		{status: http.StatusCreated},
		{status: http.StatusNoContent},
		{status: http.StatusNotFound, wantErr: true},
		{status: http.StatusInternalServerError, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			webhookreqSuccessfulCounter = prometheus.NewCounter(prometheus.CounterOpts{Name: "test_webhook_requests_successful"})

			err := newTestRouter(t, srv.URL, nil, nil).SendWebhook(testAlert)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SendWebhook error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("SendWebhook error %q does not mention HTTP status %d", err, tc.status)
			}

			wantCount := 1.0
			if tc.wantErr {
				wantCount = 0
			}
			var m dto.Metric
			if err := webhookreqSuccessfulCounter.Write(&m); err != nil {
				t.Fatalf("Error reading successful webhook counter: %v", err)
			}
			if got := m.GetCounter().GetValue(); got != wantCount {
				t.Errorf("successful webhook counter = %v, want %v", got, wantCount)
			}
		})
	}
}
