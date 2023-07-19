/*
 * Code holding/handling the Alertmanager native webhook format
 */
package alerts

import (
	"errors"
	"log"
	"net/url"
	"os"
	"strings"
)

// Supports Alertmanager webhook versions: 4

/*
 * RoutingConfig is a central feature for this software; Alertmanager alerts often have a pre-canned URL scheme that references the internal k8s hostname and namespace,
 * but these are not accessible outside the cluster.  By using a URL transmutation scheme, we can adapt all alert-specific URLs to use a different URL scheme, perhaps
 * involving an external load balancer for the Alertmanager & Prometheus instances or perhaps utilizing the Kubernetes API Service proxy, possibly with a higher-level
 * cluster proxy such as Rancher on top of it.  This allows users to click links in alerts and have them route to a workable URL, without requiring reconfiguration of
 * the Alertmanager software.
 */
type RoutingConfig struct {
	AlertmanagerBaseURL string
	PrometheusBaseURL   string

	urlrepAlertmanager *URLReplacements
	urlrepPrometheus   *URLReplacements
}

// Global set of alertmanager & prometheus URL transmute objects; configured on software startup
var GlobalRoutingConfig *RoutingConfig

// Initialization function that should be run after the GlobalRoutingConfig URL strings are set
func ParseRoutingConfigs(alertmanagerURL string, prometheusURL string) error {
	if GlobalRoutingConfig == nil {
		GlobalRoutingConfig = new(RoutingConfig)
	}
	GlobalRoutingConfig.AlertmanagerBaseURL = alertmanagerURL
	GlobalRoutingConfig.PrometheusBaseURL = prometheusURL

	GlobalRoutingConfig.urlrepAlertmanager = &URLReplacements{
		NewURLPrefix: GlobalRoutingConfig.AlertmanagerBaseURL,
	}
	if err := GlobalRoutingConfig.urlrepAlertmanager.Parse(); err != nil {
		return err
	}
	GlobalRoutingConfig.urlrepPrometheus = &URLReplacements{
		NewURLPrefix: GlobalRoutingConfig.PrometheusBaseURL,
	}
	if err := GlobalRoutingConfig.urlrepPrometheus.Parse(); err != nil {
		return err
	}
	return nil
}

func (r *RoutingConfig) IsInitialized() bool {
	if r == nil || r.urlrepAlertmanager == nil || r.urlrepPrometheus == nil {
		return false
	}
	return true
}

/*
	{
	  "version": "4",
	  "groupKey": <string>,              // key identifying the group of alerts (e.g. to deduplicate)
	  "truncatedAlerts": <int>,          // how many alerts have been truncated due to "max_alerts"
	  "status": "<resolved|firing>",
	  "receiver": <string>,
	  "groupLabels": <object>,
	  "commonLabels": <object>,
	  "commonAnnotations": <object>,
	  "externalURL": <string>,           // backlink to the Alertmanager.
	  "alerts": [
	    {
	      "status": "<resolved|firing>",
	      "labels": <object>,
	      "annotations": <object>,
	      "startsAt": "<rfc3339>",
	      "endsAt": "<rfc3339>",
	      "generatorURL": <string>,      // identifies the entity that caused the alert
	      "fingerprint": <string>        // fingerprint to identify the alert
	    },
	    ...
	  ]
	}
*/
type AlertmanagerWebhookInputV4 struct {
	Version             string                 `yaml:"version"`
	GroupKey            string                 `yaml:"groupKey"`
	TruncatedAlertCount int                    `yaml:"truncatedAlerts"`
	Status              string                 `yaml:"status"` // enum: resolved, firing
	Receiver            string                 `yaml:"receiver"`
	GroupLabels         map[string]string      `yaml:"groupLabels"`       // K=V map
	CommonLabels        map[string]string      `yaml:"commonLabels"`      // K=V map
	CommonAnnotations   map[string]string      `yaml:"commonAnnotations"` // K=V map
	ExternalURL         string                 `yaml:"externalURL"`
	Alerts              []*AlertmanagerAlertV4 `yaml:"alerts"`
}

type AlertmanagerWebhookVersionInvalid string

func (a AlertmanagerWebhookVersionInvalid) Error() string {
	return "Alertmanager Webhook returned invalid version: " + string(a)
}

type AlertmanagerAlertV4 struct {
	Status               string            `yaml:"status"`      // enum: resolved, firing
	Labels               map[string]string `yaml:"labels"`      // K=V map
	Annotations          map[string]string `yaml:"annotations"` // K=V map
	StartsAt             string            `yaml:"startsAt"`
	EndsAt               string            `yaml:"endsAt"`
	GeneratorURL         string            `yaml:"generatorURL"`
	OriginalGeneratorURL string            // Used by the AlertmanagerWebhookTemplateV4 to capture the non-transmuted prometheus URL
	Fingerprint          string            `yaml:"fingerprint"`
}

type AlertmanagerWebhookTemplateV4 struct {
	Version             string            `yaml:"version"`
	GroupKey            string            `yaml:"groupKey"`
	TruncatedAlertCount int               `yaml:"truncatedAlerts"`
	Status              string            `yaml:"status"` // enum: resolved, firing
	Receiver            string            `yaml:"receiver"`
	GroupLabels         map[string]string `yaml:"groupLabels"`       // K=V map
	CommonLabels        map[string]string `yaml:"commonLabels"`      // K=V map
	CommonAnnotations   map[string]string `yaml:"commonAnnotations"` // K=V map
	ExternalURL         string            `yaml:"externalURL"`
	OriginalExternalURL string
	Alerts              []*AlertmanagerAlertV4 `yaml:"alerts"`
	Env                 map[string]string
}

// Prepare is the operative function to take an accepted Alertmanager webhook request and "format" it to execute
// as data to the template function.  URLs are transmuted, OS environment is added.
func (a *AlertmanagerWebhookInputV4) Prepare() (*AlertmanagerWebhookTemplateV4, error) {
	if a.Version != "4" {
		return nil, AlertmanagerWebhookVersionInvalid(a.Version)
	}
	if !GlobalRoutingConfig.IsInitialized() {
		return nil, errors.New("URL routing config for webhook processor is not initialized")
	}

	tmpval := new(AlertmanagerWebhookTemplateV4)

	tmpval.Version = a.Version
	tmpval.GroupKey = a.GroupKey
	tmpval.TruncatedAlertCount = a.TruncatedAlertCount
	tmpval.Status = a.Status
	tmpval.Receiver = a.Receiver
	tmpval.GroupLabels = a.GroupLabels
	tmpval.CommonLabels = a.CommonLabels
	tmpval.CommonAnnotations = a.CommonAnnotations
	// Transmute alertmanager URL in ExternalURL
	tmpval.ExternalURL = GlobalRoutingConfig.urlrepAlertmanager.Transmute(a.ExternalURL)
	tmpval.OriginalExternalURL = a.ExternalURL
	// Transmute prometheus URL in each alert's GeneratorURL
	for _, l := range a.Alerts {
		newAlert := &AlertmanagerAlertV4{
			Status:      l.Status,
			Labels:      l.Labels,
			Annotations: l.Annotations,
			StartsAt:    l.StartsAt,
			EndsAt:      l.EndsAt,
			Fingerprint: l.Fingerprint,
		}
		newAlert.GeneratorURL = GlobalRoutingConfig.urlrepPrometheus.Transmute(l.GeneratorURL)
		newAlert.OriginalGeneratorURL = l.GeneratorURL
		tmpval.Alerts = append(tmpval.Alerts, newAlert)
	}

	// Add the current process's environment variables to the object so they may be referenced in templates
	processEnvironment := os.Environ()
	tmpval.Env = make(map[string]string, len(processEnvironment))
	for _, e := range processEnvironment {
		// Environ returns a string array of K=V strings; must parse each one
		v := strings.SplitN(e, "=", 2)
		if len(v) > 1 {
			tmpval.Env[v[0]] = v[1]
		}
	}

	return tmpval, nil
}

type URLReplacements struct {
	NewURLPrefix     string `yaml:"prefix"`
	newURLComponents *url.URL
}

func (u *URLReplacements) Parse() error {
	url, err := url.Parse(u.NewURLPrefix)
	if err != nil {
		return err
	}
	u.newURLComponents = url
	return nil
}

// Main function for URLReplacements is to transmute a URL into the intended usable form.
func (u *URLReplacements) Transmute(in string) string {
	if u.newURLComponents == nil {
		if err := u.Parse(); err != nil {
			log.Printf("URLReplacements.Transmute warning: Running URLReplacements.Parse() returned error: %v\n", err)
			return ""
		}
	}
	url, err := url.Parse(in)
	if err != nil {
		log.Printf("URLReplacements.Transmute warning: cannot parse input string [%s] as a URL\n", err)
		return ""
	}

	newURL := u.newURLComponents
	newURL = newURL.JoinPath(url.EscapedPath())
	// Preserve query strings & # fragments
	newURL.RawQuery = url.RawQuery
	newURL.RawFragment = url.RawFragment
	newURL.Fragment = url.Fragment
	if url.ForceQuery {
		newURL.ForceQuery = true
	}
	return newURL.String()
}
