// webhook_server addresses the handling of incoming Alertmanager webhooks and the outbound template processing of them
package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spirilis/spitter/alerts"
	"gopkg.in/yaml.v2"
)

type WebhookRouter struct {
	DestURL        string                 `yaml:"url"`
	HttpMethod     string                 `yaml:"method"`
	Template       string                 `yaml:"template"`
	ContentType    string                 `yaml:"contentType,omitempty"`
	Authentication *WebhookAuthentication `yaml:"auth,omitempty"`
	Matchers       []*WebhookMatcher      `yaml:"matchers"`
}

func (r *WebhookRouter) Check() error {
	if r == nil {
		return errors.New("nil object")
	}
	if r.DestURL == "" {
		return errors.New("missing URL")
	}
	if r.Template == "" {
		return errors.New("no template")
	}
	if len(r.Matchers) < 1 {
		return errors.New("no label matchers")
	}
	return nil
}

type WebhookAuthentication struct {
	BearerToken         string            `yaml:"token,omitempty"`
	BearerTokenFromFile string            `yaml:"tokenFile,omitempty"`
	Cookies             map[string]string `yaml:"cookies,omitempty"`
}

func (wa *WebhookAuthentication) ResolveBearerToken() error {
	if wa.BearerTokenFromFile != "" {
		contents, err := os.ReadFile(wa.BearerTokenFromFile)
		if err != nil {
			if DEBUGLEVEL_DEBUG {
				log.Printf("WebhookAuthentication.ResolveBearerToken experienced error [%v] reading bearer token file %s", err, wa.BearerTokenFromFile)
			}
			return err
		}
		wa.BearerToken = string(contents)
	}
	return nil
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

func (r *WebhookRouter) SendWebhook(a *alerts.AlertmanagerWebhookTemplateV4) error {
	b := &bytes.Buffer{}
	b.Grow(len(r.Template)) // Not exact but hopefully accurate enough to reduce the # of memory reallocations

	tp := template.Must(template.New("sendwebhook").Funcs(sprig.FuncMap()).Parse(r.Template))
	if err := tp.Execute(b, a); err == nil {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		transport := &http.Transport{
			TLSClientConfig: tlsConfig,
		}
		client := &http.Client{
			Transport: transport,
		}
		req, err := http.NewRequest(r.HttpMethod, r.DestURL, b)
		if err != nil {
			if DEBUGLEVEL_DEBUG {
				log.Printf("WebhookRouter.SendWebhook error - cannot create an HTTP Request object for reason [%v]", err)
			}
			return fmt.Errorf("WebhookRouter.SendWebhook http.NewRequest error %v", err)
		}

		// Configure request parameters - content-type, cookies and/or bearer token
		req.Header.Set("Content-Type", r.ContentType)
		if r.Authentication.BearerToken != "" {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.Authentication.BearerToken))
		}
		if r.Authentication.Cookies != nil && len(r.Authentication.Cookies) > 0 {
			for k, v := range r.Authentication.Cookies {
				req.AddCookie(&http.Cookie{
					Name:  k,
					Value: v,
				})
			}
		}

		// Submit HTTP/HTTPS request
		resp, err := client.Do(req)
		if err != nil {
			if DEBUGLEVEL_DEBUG {
				log.Printf("WebhookRouter.SendWebhook error submitting HTTP request: %v", err)
			}
			return fmt.Errorf("WebhookRouter.SendWebhook error submitting HTTP request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			if DEBUGLEVEL_DEBUG {
				respData, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Printf("WebhookRouter.SendWebhook HTTP request returned non-200 code %d; response not available due to error [%v]", resp.StatusCode, err)
				} else {
					log.Printf("WebhookRouter.SendWebhook HTTP request returned non-200 code %d; response=%s", resp.StatusCode, respData)
				}
			}
		}

		// Successful send
		webhookreqSuccessfulMutex.Lock()
		webhookreqSuccessfulCounter.Inc()
		webhookreqSuccessfulMutex.Unlock()

		if DEBUGLEVEL_TRACE {
			respData, err := io.ReadAll(resp.Body)
			if err != nil {
				respData = []byte("")
			}
			log.Printf("WebhookRouter.SendWebhook successful send: URL=%s; method=%s; response=%s", r.DestURL, r.HttpMethod, respData)
		}
	} else {
		if DEBUGLEVEL_DEBUG {
			log.Printf("WebhookRouter.SendWebhook failed to execute template for reason [%v] on data [%#v]", err, a)
		}
		return fmt.Errorf("WebhookRouter.SendWebhook template Execute error %v", err)
	}
	return nil
}

// Webhook server

type WebhookServer struct {
	Listen                    *WebhookServerListen  `yaml:"listen,omitempty"`
	AlertmanagerURL           string                `yaml:"alertmanagerURL"`
	PrometheusURL             string                `yaml:"prometheusURL"`
	Routers                   []*WebhookRouter      `yaml:"routers,omitempty"`
	AdditionalRouterDirectory string                `yaml:"addlRouterDir,omitempty"`
	Metrics                   *WebhookServerMetrics `yaml:"metrics,omitempty"`
	allRouters                []*WebhookRouter
}

var GlobalWebhookServer *WebhookServer

type WebhookServerListen struct {
	Hostname string `yaml:"host,omitempty"`
	Port     int    `yaml:"port,omitempty"`
}

type WebhookServerMetrics struct {
	URI         string `yaml:"path,omitempty"`
	Token       string `yaml:"token,omitempty"`
	TokenEnvVar string `yaml:"tokenEnv,omitempty"`
}

func (w *WebhookServer) Start() error {
	if w == nil {
		return errors.New("WebhookServer.Start error - nil WebhookServer object")
	}
	if w.Listen == nil {
		w.Listen = &WebhookServerListen{Hostname: "127.0.0.1", Port: 9820}
	}
	if w.AlertmanagerURL == "" {
		return errors.New("WebhookServer.Start error - We expect a valid URL to the alertmanager instance")
	}
	if w.PrometheusURL == "" {
		return errors.New("WebhookServer.Start error - We expect a valid URL to the prometheus instance")
	}
	if w.Routers == nil && w.AdditionalRouterDirectory == "" {
		return errors.New("WebhookServer.Start error - No routers specified")
	}

	err := alerts.ParseRoutingConfigs(w.AlertmanagerURL, w.PrometheusURL, ApplicationName)
	if err != nil {
		return fmt.Errorf("WebhookServer.Start had an error initializing the alerts routing configs: %v", err)
	}

	// Read the specified set of routers, check for consistency, apply default HTTP method if relevant, and add to the array
	routersRejected := 0
	for _, rt := range w.Routers {
		if rt.Check() != nil {
			routersRejected++
			continue
		}
		if rt.HttpMethod == "" {
			rt.HttpMethod = "POST"
		}
		if rt.ContentType == "" {
			rt.ContentType = "application/json"
		}
		if rt.Authentication.ResolveBearerToken() != nil {
			routersRejected++
			continue
		}
		w.allRouters = append(w.allRouters, rt)
	}
	if w.AdditionalRouterDirectory != "" {
		// Read every file in this directory and attempt to unmarshal it into a WebhookRouter object; if it fails, ignore and just keep going
		files, err := os.ReadDir(w.AdditionalRouterDirectory)
		if err != nil {
			return fmt.Errorf("WebhookServer.Start had an error reading router configs from directory [%s]: %v", w.AdditionalRouterDirectory, err)
		}
		for _, file := range files {
			if !file.IsDir() {
				filename := file.Name()
				contents, err := os.ReadFile(w.AdditionalRouterDirectory + "/" + filename)
				if err == nil {
					b := bytes.NewBuffer(contents)
					dec := yaml.NewDecoder(b)
					n := new(WebhookRouter)
					err = dec.Decode(n)
					if err == nil {
						// Lint the object to make sure it has the minimum fields
						if n.Check() == nil {
							// Check doesn't verify HTTP Method since we assume POST as a default here.
							if n.HttpMethod == "" {
								n.HttpMethod = "POST"
							}
							if n.ContentType == "" {
								n.ContentType = "application/json"
							}
							if n.Authentication.ResolveBearerToken() != nil {
								routersRejected++
							} else {
								w.allRouters = append(w.allRouters, n)
							}
						} else {
							routersRejected++
						}
					}
				}
			}
		}
	}

	if len(w.allRouters) < 1 {
		return errors.New("WebhookServer.Start error - No valid routers present")
	}

	// Set some initial prometheus metrics relevant to startup
	c := promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_routers",
		Help: "This is the number of webhook router configs defined in the running spitter instance",
	})
	prometheus.MustRegister(c)
	c.Set(float64(len(w.allRouters)))

	c = promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_routers_rejected",
		Help: "This is the number of webhook router configs viewed - either in app config or found as valid routers in the additional router config directory - and determined unworkable",
	})
	prometheus.MustRegister(c)
	c.Set(float64(routersRejected))

	// connectionMutex, connectionGauge defined further below near the main API handler function
	connectionMutex.Lock()
	connectionGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_connections",
		Help: "Number of active connections to the webhook router (active connections from an Alertmanager)",
	})
	prometheus.MustRegister(connectionGauge)
	connectionGauge.Set(0)
	connectionMutex.Unlock()

	connectionCountMutex.Lock()
	connectionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests",
		Help: "Total number of webhook requests seen",
	})
	prometheus.MustRegister(connectionCounter)
	connectionCountMutex.Unlock()

	// webhookreq* mutex and prometheus metric variables defined further below near main API handler function
	webhookreqAttemptedMutex.Lock()
	webhookreqAttemptedCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests_attempted",
		Help: "Number of webhook requests received by Alertmanager where a router was matched and attempted",
	})
	prometheus.MustRegister(webhookreqAttemptedCounter)
	webhookreqAttemptedMutex.Unlock()

	webhookreqSuccessfulMutex.Lock()
	webhookreqSuccessfulCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests_successful",
		Help: "Number of webhook requests received by Alertmanager where a router was matched and successfully routed",
	})
	prometheus.MustRegister(webhookreqSuccessfulCounter)
	webhookreqSuccessfulMutex.Unlock()

	// Set up Prometheus metrics config
	if w.Metrics == nil {
		w.Metrics = &WebhookServerMetrics{
			URI: "/metrics",
		}
	} else {
		if w.Metrics.URI == "" {
			w.Metrics.URI = "/metrics"
		}
	}

	// Set up HTTP handlers
	http.HandleFunc("/healthz", handleHealthz)
	http.Handle(w.Metrics.URI, promhttp.Handler())
	http.HandleFunc("/v4/alertmanager/webhook", handleWebhooksV4)
	// TODO: http.HandleFunc("/v4/alertmanager/routers", handleListRoutersV4) as a GET request to list all our configured routers

	GlobalWebhookServer = w // so the handler functions can find us
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", w.Listen.Hostname, w.Listen.Port), nil))
	return nil
}

func (w *WebhookServer) GetRouters() []*WebhookRouter {
	return w.allRouters
}

var healthzMutex sync.Mutex
var healthzCounter prometheus.Counter

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	healthzMutex.Lock()
	healthzCounter.Inc()
	healthzMutex.Unlock()

	if DEBUGLEVEL_TRACE {
		log.Printf("Received healthz request [%#v]", r)
	}
	w.WriteHeader(http.StatusOK)
}

var connectionMutex sync.Mutex
var connectionGauge prometheus.Gauge
var connectionCountMutex sync.Mutex
var connectionCounter prometheus.Counter

var webhookreqAttemptedMutex sync.Mutex
var webhookreqAttemptedCounter prometheus.Counter

var webhookreqSuccessfulMutex sync.Mutex
var webhookreqSuccessfulCounter prometheus.Counter

func handleWebhooksV4(w http.ResponseWriter, r *http.Request) {
	// Handle initial connection-related Prometheus counters
	connectionMutex.Lock()
	connectionGauge.Inc()
	connectionMutex.Unlock()

	defer func() {
		connectionMutex.Lock()
		connectionGauge.Dec()
		connectionMutex.Unlock()
	}()

	connectionCountMutex.Lock()
	connectionCounter.Inc()
	connectionCountMutex.Unlock()

	// Handle actual application logic

	// POST only allowed
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		if DEBUGLEVEL_DEBUG {
			log.Printf("Received HTTP request with invalid method [%s] - expecting POST", r.Method)
		}
		fmt.Fprintf(w, "Invalid request method [%s] - we only expect the use of POST with this endpoint", r.Method)
		return
	}

	// Collect payload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if DEBUGLEVEL_DEBUG {
			log.Printf("Error reading request body [%v]", err)
		}
		fmt.Fprintf(w, "Error reading request body [%v]", err)
		return
	}

	if DEBUGLEVEL_TRACE {
		log.Printf("Received a POST payload:\nHeaders: %#v\nPostdata:\n%s\n", r.Header, body)
	}

	// Unmarshal what we expect to be an Alertmanager webhook request
	b := bytes.NewBuffer(body)
	dec := yaml.NewDecoder(b)
	alertwebhook := new(alerts.AlertmanagerWebhookInputV4)
	err = dec.Decode(alertwebhook)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error processing webhook from POST data [%v]", err)
		if DEBUGLEVEL_DEBUG {
			log.Printf("Received POST data but could not unmarshal into an AlertmanagerWebhookInputV4: %v", err)
		}
		return
	}

	if DEBUGLEVEL_TRACE {
		log.Printf("Received the following alert webhook:\n%s\n", alertwebhook.String())
	}

	// Find routers that might want to receive this
	for _, r := range GlobalWebhookServer.GetRouters() {
		hasMatching := 0
		for _, m := range r.Matchers {
			if m.HasMatchingAlerts(alertwebhook) {
				hasMatching++
			}
		}
		if hasMatching == len(r.Matchers) {
			// This router completely triggers on this alert; process it
			webhookreqAttemptedMutex.Lock()
			webhookreqAttemptedCounter.Inc()
			webhookreqAttemptedMutex.Unlock()

			templated, err := r.PrepareTemplateData(alertwebhook)
			if err == nil {
				r.SendWebhook(templated)
			} else {
				if DEBUGLEVEL_DEBUG {
					log.Printf("Attempted to route a webhook but failed: %v", err)
				}
			}
		}
	}
}
