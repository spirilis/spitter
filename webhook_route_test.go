package main

import (
	"bytes"
	"log"
	"testing"

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

func TestExampleAlertRouting1(t *testing.T) {
	webhook_router_yaml := bytes.NewBuffer([]byte(exampleRouterConfig1))
	dec := yaml.NewDecoder(webhook_router_yaml)
	webhook_router := new(WebhookRouter)
	err := dec.Decode(webhook_router)
	if err != nil {
		t.Errorf("Error decoding WebhookRouter object: %v", err)
	}

	alert_yaml := bytes.NewBuffer([]byte(exampleAlerts1))
	dec = yaml.NewDecoder(alert_yaml)
	alert := new(alerts.AlertmanagerWebhookInputV4)
	err = dec.Decode(alert)
	if err != nil {
		t.Errorf("Error decoding AlertmanagerWebhookInputV4 object: %v", err)
	}

	log.Printf("WebhookRouter: %#v\n", webhook_router)
	log.Printf("  URL: %s\n  Method: %s\n", webhook_router.DestURL, webhook_router.HttpMethod)
	log.Printf("Alertmanager Webhook Input: %#v\n", alert)
}
