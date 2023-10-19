// webhook_server addresses the handling of incoming Alertmanager webhooks and the outbound template processing of them
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spirilis/spitter/alerts"
	"gopkg.in/yaml.v2"
)

// WebhookRouter handles a single destination endpoint - a set of matchers decides which alerts get routed to this destination.
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
	if r.Authentication == nil {
		r.Authentication = &WebhookAuthentication{}
	}
	return nil
}

type WebhookAuthentication struct {
	BearerToken         string            `yaml:"token,omitempty"`
	BearerTokenFromFile string            `yaml:"tokenFile,omitempty"`
	BasicAuth           WebhookBasicAuth  `yaml:"basicAuth,omitempty"`
	Cookies             map[string]string `yaml:"cookies,omitempty"`
}

type WebhookBasicAuth struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func (a WebhookBasicAuth) AuthorizationHeader() string {
	return "Basic " + string(base64.StdEncoding.EncodeToString([]byte(a.Username+":"+a.Password)))
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

func (wa *WebhookAuthentication) AuthorizationHeader() string {
	if wa.BearerToken != "" {
		return "Bearer " + wa.BearerToken
	}
	if wa.BasicAuth.Username != "" && wa.BasicAuth.Password != "" {
		return "Basic " + wa.BasicAuth.AuthorizationHeader()
	}
	return ""
}

// WebhookRouter's Matcher system defined here-
type WebhookMatcher struct {
	Label          string `yaml:"label"`
	MatchString    string `yaml:"match,omitempty"`
	MatchRegexp    string `yaml:"match_re,omitempty"`
	compiledRegexp *regexp.Regexp
}

func (m *WebhookMatcher) String() string {
	if m == nil {
		return "nil"
	}
	var out string

	out = m.Label
	if m.MatchString != "" {
		out += "=" + m.MatchString
		return out
	}
	if m.MatchRegexp != "" {
		out += "=~" + m.MatchRegexp
		return out
	}
	return out + " <can't match>"
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

// This accepts an input Alertmanager webhook and prepares it for consumption by the router's template-
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

// Operational function to execute the router's template and submit the webhook to its destination
func (r *WebhookRouter) SendWebhook(a *alerts.AlertmanagerWebhookTemplateV4) error {
	b := &bytes.Buffer{}
	b.Grow(len(r.Template)) // Not exact but hopefully accurate enough to reduce the # of memory reallocations

	tp := template.Must(template.New("sendwebhook").Funcs(sprig.FuncMap()).Parse(r.Template))
	if err := tp.Execute(b, a); err == nil {
        if DEBUGLEVEL_TRACE {
            log.Printf("WebhookRouter.SendWebhook- Trace dumping template output:\n---\n%s\n---\n", b.String())
        }
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
			req.Header.Set("Authorization", r.Authentication.AuthorizationHeader())
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
	ReloadTriggerFile         string                `yaml:"reloadTriggerFile,omitempty"`
	Metrics                   *WebhookServerMetrics `yaml:"metrics,omitempty"`
	allRouters                []*WebhookRouter
}

var GlobalWebhookServer *WebhookServer

type WebhookServerListen struct {
	Hostname string `yaml:"host,omitempty"`
	Port     int    `yaml:"port,omitempty"`
}

type WebhookServerMetrics struct {
	URI   string `yaml:"path,omitempty"`
	Token string `yaml:"token,omitempty"`
}

// Loading and interpretation of the routers has been offloaded to a separate function to facilitate the re-loading of config during runtime, using SIGHUP.
// This facilitates things such as Kubernetes operator control, dynamically updating configs.
var routersRejected int
var routerMutex sync.Mutex
var rejectedRouters prometheus.Gauge

func (w *WebhookServer) ReloadRouters() error {
	// Read the specified set of routers, check for consistency, apply default HTTP method if relevant, and add to the array
	var tmpAllRouters []*WebhookRouter
	tmpRoutersRejected := 0
	for _, rt := range w.Routers {
		if rt.Check() != nil {
			tmpRoutersRejected++
			continue
		}
		if rt.HttpMethod == "" {
			rt.HttpMethod = "POST"
		}
		if rt.ContentType == "" {
			rt.ContentType = "application/yaml"
		}
		if rt.Authentication.ResolveBearerToken() != nil {
			tmpRoutersRejected++
			continue
		}
		tmpAllRouters = append(tmpAllRouters, rt)
		if DEBUGLEVEL_DEBUG {
			log.Printf("Including router: [URL=\"%s\"|Method=%s|ContentType=\"%s\"|%d matchers]", rt.DestURL, rt.HttpMethod, rt.ContentType, len(rt.Matchers))
		}
	}
	if w.AdditionalRouterDirectory != "" {
		if DEBUGLEVEL_DEBUG {
			log.Printf("Inspecting AdditionalRouterDirectory [%s] for more routers", w.AdditionalRouterDirectory)
		}
		// Read every file in this directory and attempt to unmarshal it into a WebhookRouter object; if it fails, ignore and just keep going
		files, err := os.ReadDir(w.AdditionalRouterDirectory)
		if err == nil {
			for _, file := range files {
				if !file.IsDir() {
					filename := file.Name()
					contents, err := os.ReadFile(w.AdditionalRouterDirectory + "/" + filename)
					if err == nil {
						b := bytes.NewBuffer(contents)
						dec := yaml.NewDecoder(b)
						rt := new(WebhookRouter)
						err = dec.Decode(rt)
						if err == nil {
							// Lint the object to make sure it has the minimum fields
							if rt.Check() == nil {
								// Check doesn't verify HTTP Method since we assume POST as a default here.
								if rt.HttpMethod == "" {
									rt.HttpMethod = "POST"
								}
								if rt.ContentType == "" {
									rt.ContentType = "application/yaml"
								}
								if rt.Authentication.ResolveBearerToken() != nil {
									tmpRoutersRejected++
								} else {
									tmpAllRouters = append(tmpAllRouters, rt)
									if DEBUGLEVEL_DEBUG {
										log.Printf("Including router: [URL=\"%s\"|Method=%s|ContentType=\"%s\"|%d matchers]", rt.DestURL, rt.HttpMethod, rt.ContentType, len(rt.Matchers))
									}

								}
							} else {
								tmpRoutersRejected++
								if DEBUGLEVEL_DEBUG {
									log.Printf("Read WebhookRouter object but it failed its Check(): [%s]", file.Name())
								}
							}
						} else {
							if DEBUGLEVEL_DEBUG {
								log.Printf("Read file but could not unmarshal as WebhookRouter object: [%s]", file.Name())
							}
						}
					} else {
						if DEBUGLEVEL_TRACE {
							log.Printf("Error reading file [%s]: %v", file.Name(), err)
						}
					}
				} else {
					if DEBUGLEVEL_TRACE {
						log.Printf("Directory entry is a directory: %s", file.Name())
					}
				}
			}
		} else {
			if DEBUGLEVEL_DEBUG {
				log.Printf("WebhookServer.Start had an error reading router configs from directory [%s]: %v", w.AdditionalRouterDirectory, err)
			}
		}
	}

	if len(tmpAllRouters) < 1 {
		return errors.New("WebhookServer.ReloadRouters error - No valid routers present")
	}

	routerMutex.Lock()
	routersRejected = tmpRoutersRejected
	w.allRouters = tmpAllRouters
	routerMutex.Unlock()

	return nil
}

// Main entrypoint for the WebhookServer.
func (w *WebhookServer) Start() error {
	if w == nil {
		return errors.New("WebhookServer.Start error - nil WebhookServer object")
	}
	if w.Listen == nil {
		w.Listen = &WebhookServerListen{Hostname: "0.0.0.0", Port: 9820}
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

	// Load initial set of routers
	err = w.ReloadRouters()
	if err != nil {
		return fmt.Errorf("WebhookServer.Start had an error initializating routers: %v", err)
	}

	// Set some initial prometheus metrics relevant to startup
	c := promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_routers",
		Help: "This is the number of webhook router configs defined in the running spitter instance",
	})
	c.Set(float64(len(w.allRouters)))
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_webhook_routers", ApplicationName)
	}

	rejectedRouters = promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_routers_rejected",
		Help: "This is the number of webhook router configs viewed - either in app config or found as valid routers in the additional router config directory - and determined unworkable",
	})
	rejectedRouters.Set(float64(routersRejected))
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_webhook_routers_rejected", ApplicationName)
	}

	// connectionMutex, connectionGauge defined further below near the main API handler function
	connectionGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_connections",
		Help: "Number of active connections to the webhook router (active connections from an Alertmanager)",
	})
	connectionGauge.Set(0)
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_webhook_connections", ApplicationName)
	}

	connectionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests",
		Help: "Total number of webhook requests seen",
	})
	prometheus.MustRegister(connectionCounter)
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_webhook_requests", ApplicationName)
	}

	healthzCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_healthz_count",
		Help: "Total number of /healthz health check requests",
	})
	prometheus.MustRegister(healthzCounter)
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_healthz_count", ApplicationName)
	}

	// webhookreq* mutex and prometheus metric variables defined further below near main API handler function
	webhookreqAttemptedCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests_attempted",
		Help: "Number of webhook requests received by Alertmanager where a router was matched and attempted",
	})
	prometheus.MustRegister(webhookreqAttemptedCounter)
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_webhook_requests_attempted", ApplicationName)
	}

	webhookreqSuccessfulCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests_successful",
		Help: "Number of webhook requests received by Alertmanager where a router was matched and successfully routed",
	})
	prometheus.MustRegister(webhookreqSuccessfulCounter)
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_webhook_requests_successful", ApplicationName)
	}

	// Set up SIGHUP handler for reloading routers
	hupChan := make(chan os.Signal, 4)
	go func(hupchan chan os.Signal, w *WebhookServer) {
		for {
			<-hupchan
			if DEBUGLEVEL_TRACE {
				log.Println("SIGHUP received")
			}
			err := w.ReloadRouters()
			if err != nil {
				// True to the same behavior as .Start(), if there are no routers defined, we bomb.
				// K8s would show this as a continual restart followed by a CrashLoopBackoff, most likely.  Hopefully that'll get someone's attention.
				panic("SIGHUP router reload ended in error: " + err.Error())
			}
			routerMutex.Lock()
			rejectedRouters.Set(float64(routersRejected))
			routerMutex.Unlock()
		}
	}(hupChan, w)
	signal.Notify(hupChan, syscall.SIGHUP)
	if DEBUGLEVEL_DEBUG {
		log.Println("Listening for SIGHUP to reload the router list")
	}

	// Set up ReloadTriggerFile watcher for reloading routers
	if w.ReloadTriggerFile != "" {
		go func(watchFile string, w *WebhookServer) {
			for {
				f, err := os.Open(watchFile)
				if err == nil {
					// File exists!  Close it, reload routers, delete the file
					f.Close()
					err = w.ReloadRouters()
					if err != nil {
						// True to the same behavior as .Start(), if there are no routers defined, we bomb.
						// K8s would show this as a continual restart followed by a CrashLoopBackoff, most likely.  Hopefully that'll get someone's attention.
						panic("Reload trigger-initiated router reload ended in error: " + err.Error())
					}
					routerMutex.Lock()
					rejectedRouters.Set(float64(routersRejected))
					routerMutex.Unlock()
					err = os.Remove(watchFile)
					if err != nil {
						panicMsg := fmt.Sprintf("Issuing os.Remove(%s) on reload-trigger file ended in error: %v", watchFile, err)
						panic(panicMsg)
					}
				}
				time.Sleep(5 * time.Second)
			}
		}(w.ReloadTriggerFile, w)
		if DEBUGLEVEL_DEBUG {
			log.Printf("Watching every 5 seconds for trigger file [%s] to reload the router list", w.ReloadTriggerFile)
		}
	}

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
	var allURIs []string

	http.HandleFunc("/healthz", handleHealthz)
	allURIs = append(allURIs, "/healthz")

	http.Handle(w.Metrics.URI, promhttp.Handler())
	allURIs = append(allURIs, w.Metrics.URI)

	http.HandleFunc("/v4/alertmanager/webhook", handleWebhooksV4)
	allURIs = append(allURIs, "/v4/alertmanager/webhook")
	// TODO: http.HandleFunc("/v4/alertmanager/routers", handleListRoutersV4) as a GET request to list all our configured routers

	GlobalWebhookServer = w // so the handler functions can find us
	listenStr := fmt.Sprintf("%s:%d", w.Listen.Hostname, w.Listen.Port)
	if DEBUGLEVEL_INFO {
		log.Printf("WebhookServer listening on: %s\n", listenStr)
	}
	if DEBUGLEVEL_DEBUG {
		log.Printf("All URIs: %#v\n", allURIs)
	}
	log.Fatal(http.ListenAndServe(listenStr, nil))
	return nil
}

func (w *WebhookServer) GetRouters() []*WebhookRouter {
	return w.allRouters
}

// HealthZ for readiness probes
var healthzMutex sync.Mutex
var healthzCounter prometheus.Counter

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	healthzMutex.Lock()
	healthzCounter.Inc()
	healthzMutex.Unlock()

	if DEBUGLEVEL_TRACE && ENABLE_HEALTHZ_DEBUG {
		log.Printf("Received healthz request [%#v]", r)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Up\n"))
}

// Handle incoming Alertmanager Webhooks, find which routers match and use their .SendWebhook function to send it out.
// This is done sequentially.
// TODO: Should we parallelize it with goroutines?
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
		fmt.Fprintf(w, "Invalid request method [%s] - we only expect the use of POST with this endpoint\r\n", r.Method)
		return
	}

	// Collect payload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		if DEBUGLEVEL_DEBUG {
			log.Printf("Error reading request body [%v]", err)
		}
		fmt.Fprintf(w, "Error reading request body [%v]\r\n", err)
		return
	}
	defer r.Body.Close()

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
		fmt.Fprintf(w, "Error processing webhook from POST data [%v]\r\n", err)
		if DEBUGLEVEL_DEBUG {
			log.Printf("Received POST data but could not unmarshal into an AlertmanagerWebhookInputV4: %v", err)
		}
		return
	}

	if DEBUGLEVEL_TRACE {
		log.Printf("Received the following alert webhook:\n%s\n", alertwebhook.String())
	}

	// Find routers that might want to receive this
	if DEBUGLEVEL_TRACE {
		log.Printf("Processing through %d routers-", len(GlobalWebhookServer.GetRouters()))
	}
	for _, r := range GlobalWebhookServer.GetRouters() {
		hasMatching := 0
		for _, m := range r.Matchers {
			if DEBUGLEVEL_TRACE {
				log.Printf("evaluating matcher: %s\n", m.String())
			}
			if m.HasMatchingAlerts(alertwebhook) {
				hasMatching++
			}
		}
		if DEBUGLEVEL_TRACE {
			log.Printf("evaluating webhook against router: found %d matchers that matched vs %d matchers\n", hasMatching, len(r.Matchers))
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

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("\r\n"))
}
