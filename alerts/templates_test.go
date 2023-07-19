/*
 * Templating code for spitter - used for composing JSON REST API payloads in response to Alertmanager alerts
 */
package alerts

import (
	"bytes"
	"log"
	"os"
	"testing"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v2"
)

var testTemp = `
{
	[
		{{range .Items -}}
		{{ . | upper }}
		{{end}}
	]
}
`

func TestBasicTemplate(t *testing.T) {
	tp := template.Must(template.New("test").Funcs(sprig.FuncMap()).Parse(testTemp))
	var data struct {
		Items    []string `json:"items"`
		Response string   `json:"response"`
	}
	data.Items = []string{"str1", "str2", "str3", "str4"}
	if err := tp.Execute(os.Stdout, data); err != nil {
		t.Errorf("Error executing template: %v", err)
	}
}

var stockURL = `http://alertmanager.monitoring-system:9093/alerts#123`
var replURL = `https://rancher2.mydomain.com/k8s/clusters/c-abcdef/api/v1/namespaces/monitoring-system/services/http:alertmanager:9093/proxy`

func TestURLTransmute(t *testing.T) {
	ur := &URLReplacements{
		NewURLPrefix: replURL,
	}

	err := ur.Parse()
	if err != nil {
		t.Errorf("Error parsing replacement URL components: %v", err)
	}

	transmuted := ur.Transmute(stockURL)
	if transmuted == "" {
		t.Errorf("Error: ur.Transmute returned an empty string, usually a sign of failure")
	}
	log.Printf("Transmuted URL: %s\n", transmuted)
}

var exampleAlert1 = `
{
	"version": "4",
	"groupKey": "asdf",
	"truncatedAlerts": 5,
	"status": "firing",
	"receiver": "fdsa",
	"groupLabels": {
		"job": "test1",
		"prometheus": "rancher-monitoring-prometheus"
	},
	"commonLabels": {
		"myalert": "true"
	},
	"commonAnnotations": {
		"summary": "This is a test alert"
	},
	"externalURL": "http://rancher-monitoring-alertmanager.cattle-monitoring-system:9093/alerts",
	"alerts": [
		{
			"status": "firing",
			"labels": {
				"namespace": "kube-system",
				"pod": "aws-node-abcdef",
				"uid": "12345678-1234-abcd-efghijkl",
				"alertname": "PodTestComplete"
			},
			"annotations": {
				"runbook": "https://my-wiki-page.example.com/wiki/AwsNodeTroubleshooting"
			},
			"startsAt": "asdf",
			"endsAt": "asdf",
			"generatorURL": "http://rancher-monitoring-prometheus.cattle-monitoring-system:9090/graph?g0.expr=kube_pod_info%7Bnamespace%3D\"kube-system\"%2Cpod%3D~\"aws-node-.*\"%7D&g0.tab=1&g0.stacked=0&g0.show_exemplars=0&g0.range_input=1h",
			"fingerprint": "asdffdsajkl"
		},
		{
			"status": "resolved",
			"labels": {
				"namespace": "default",
				"pod": "my-pod-12345",
				"uid": "efghijkl--1234-abcd-12345678",
				"alertname": "PodTestComplete"
			},
			"annotations": {
				"runbook": "https://my-wiki-page.example.com/wiki/GenericApplicationTroubleshooting",
				"runbook_summary": "Troubleshoot this using standard kubectl tools"
			},
			"startsAt": "asdf",
			"endsAt": "asdf",
			"generatorURL": "http://rancher-monitoring-prometheus.cattle-monitoring-system:9090/graph?g0.expr=kube_pod_info%7Bnamespace%3D\"default\"%2Cpod%3D~\"my-pod-.*\"%7D&g0.tab=1&g0.stacked=0&g0.show_exemplars=0&g0.range_input=1h",
			"fingerprint": "fdsaasdfjkl"
		}
	]
}
`

var exampleTemplateUsingAlert1 = `
GroupKey: {{.GroupKey}}
Status: {{.Status}}
Alertmanager URL: {{.ExternalURL}}
Alert summary:
{{- range .Alerts }}
  {{- if .Labels.alertname }}
  Alert: {{ .Labels.alertname }}
  {{ end -}}
  Status: {{ .Status }}
  Namespace: {{ .Labels.namespace }}
  Pod: {{ .Labels.pod }}
  {{- if .Annotations.runbook_summary }}
  TL;DR: {{ .Annotations.runbook_summary }}
  {{- end }}
  Prometheus: {{ .GeneratorURL }}
  ---
{{- end }}
`

func TestResolvingAlert1Template(t *testing.T) {
	b := bytes.NewBuffer([]byte(exampleAlert1))
	dec := yaml.NewDecoder(b)
	n := new(AlertmanagerWebhookInputV4)
	err := dec.Decode(n)
	if err != nil {
		t.Errorf("Error decoding Alertmanager webhook object: %v", err)
	}

	log.Printf("Alertmanager webhook: %#v\n", n)

	// Configure GlobalRouting for the alerts system
	err = ParseRoutingConfigs(
		"https://rancher2.my-company.com/k8s/clusters/c-asdfg/api/v1/namespaces/monitoring-system/services/http:rancher-monitoring-alertmanager:9093/proxy",
		"https://rancher2.my-company.com/k8s/clusters/c-asdfg/api/v1/namespaces/monitoring-system/services/http:rancher-monitoring-prometheus:9090/proxy",
	)
	if err != nil {
		t.Errorf("Error configuring GlobalRoutingConfig - %v", err)
	}

	processed, err := n.Prepare()
	if err != nil {
		t.Errorf("Error preparing the alert data for template: %v", err)
	}

	log.Println("Processing template-")

	tp := template.Must(template.New("test").Funcs(sprig.FuncMap()).Parse(exampleTemplateUsingAlert1))
	if err := tp.Execute(os.Stdout, processed); err != nil {
		t.Errorf("Error executing template: %v", err)
	}

}
