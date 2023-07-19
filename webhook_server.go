// webhook_server addresses the handling of incoming Alertmanager webhooks and the outbound template processing of them
package main

import (
	"errors"
	"fmt"
	"log"
	"regexp"

	"github.com/spirilis/spitter/alerts"
)

type WebhookRouter struct {
	DestURL    string            `yaml:"url"`
	HttpMethod string            `yaml:"method"`
	Template   string            `yaml:"template"`
	Matchers   []*WebhookMatcher `yaml:"matchers"`
}

type WebhookMatcher struct {
	Label          string `json:"label"`
	MatchString    string `json:"match,omitempty"`
	MatchRegexp    string `json:"match_re,omitempty"`
	compiledRegexp *regexp.Regexp
}

// One way to analyze if an alert is good; check all matchers in a router to see if this is true
func (m *WebhookMatcher) HasMatchingAlerts(a *alerts.AlertmanagerWebhookInputV4) bool {
	if a == nil || m == nil {
		return false
	}

	// Search CommonLabels, and search every alert in this object's individual labels.
	for k, v := range a.CommonLabels {
		if m.IsMatch(k, v) {
			return true
		}
	}

	for _, l := range a.Alerts {
		for k, v := range l.Labels {
			if m.IsMatch(k, v) {
				return true
			}
		}
	}

	return false
}

func (m *WebhookMatcher) IsMatch(label string, value string) bool {
	if m.Label == label {
		if m.MatchString != "" {
			if m.MatchString == value {
				return true
			}
		}
		if m.MatchRegexp != "" {
			if m.doesRegexpMatch(value) {
				return true
			}
		}
	}
	return false
}

func (m *WebhookMatcher) doesRegexpMatch(re string) bool {
	if m == nil {
		return false
	}
	if m.compiledRegexp == nil {
		rcomp, err := regexp.Compile(m.MatchRegexp)
		if err != nil {
			log.Printf("Error compiling regexp for regular expression [%s]: %v\n", m.MatchRegexp, err)
		}
		m.compiledRegexp = rcomp
	}

	return m.compiledRegexp.MatchString(re)
}

func sliceContains(sl []string, val string) bool {
	for _, s := range sl {
		if s == val {
			return true
		}
	}
	return false
}

// func mapKeyStrings(m map[string]string) []string {
// 	out := make([]string, len(m))
// 	for k := range m {
// 		out = append(out, k)
// 	}
// 	return out
// }

func (r *WebhookRouter) IsMatchingAlert(l *alerts.AlertmanagerAlertV4, matchedCommonLabels []string) bool {
	if r == nil {
		log.Println("WebhookRouter.IsMatchingAlert error - called with nil WebhookRouter")
		return false
	}
	if l == nil {
		log.Println("WebhookRouter.IsMatchingAlert error - called with nil Alert")
		return false
	}

	matchCount := 0
	for _, matcher := range r.Matchers {
		if sliceContains(matchedCommonLabels, matcher.Label) {
			// Already satisfied this one with the CommonLabels so we count it towards the total # of matched labels
			matchCount++
			continue
		}
		for k, v := range l.Labels {
			if matcher.IsMatch(k, v) {
				matchCount++
			}
		}
	}

	return matchCount != len(r.Matchers)
}

// Another way to check if an alert is good for this; check each commonLabels and alert Labels to see if this ends up true for the # of matchers we have
func (m *WebhookRouter) IsMatch(label string, value string) bool {
	if m == nil {
		log.Println("WebhookRouter.IsMatch error - called with a nil WebhookRouter")
		return false
	}

	for _, matcher := range m.Matchers {
		if matcher.IsMatch(label, value) {
			return true
		}
	}
	return false
}

func (r *WebhookRouter) PrepareTemplateData(a *alerts.AlertmanagerWebhookInputV4) (*alerts.AlertmanagerWebhookTemplateV4, error) {
	if r == nil {
		return nil, errors.New("WebhookRouter.PrepareTemplateData error: Called with a null WebhookRouter object")
	}
	if a == nil {
		return nil, errors.New("WebhookRouter.PrepareTemplateData error: Called with a null AlertmanagerWebhookInputV4 object")
	}

	// This is a slightly tricky matter - we have to create a template-ready template object, but then consider some of the alerts inside might not match all the
	// matching labels for this WebhookRouter, and we need to delete them.
	// Alternately, if all the matching labels for the WebhookRouter are satisfied by the CommonLabels, then we have little to do.

	tmpAlert, err := a.Prepare()
	if err != nil {
		return nil, fmt.Errorf("WebhookRouter.PrepareTemplateData: Error when converting the alertmanager webhook into template-ready format: %v", err)
	}

	var commonMatched []string
	for k, v := range a.CommonLabels {
		if r.IsMatch(k, v) {
			commonMatched = append(commonMatched, k)
		}
	}
	if len(commonMatched) == len(r.Matchers) {
		// All the common labels match; we're done
		return tmpAlert, nil
	}

	// Only 0 or a subset of the matchers were matched by the CommonLabels; analyze each Alert to see if it fully matches.
	var subsetAlerts []*alerts.AlertmanagerAlertV4
	for _, al := range tmpAlert.Alerts {
		// Only add an alert to the list if it fully matches our matchers list
		if r.IsMatchingAlert(al, commonMatched) {
			subsetAlerts = append(subsetAlerts, al)
		}
	}

	tmpAlert.Alerts = subsetAlerts

	return tmpAlert, nil
}

// Webhook server
