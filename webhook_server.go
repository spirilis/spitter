// webhook_server addresses the handling of incoming Alertmanager webhooks and the outbound template processing of them
package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
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
	TLS            *WebhookTLS            `yaml:"tls,omitempty"`
	Matchers       []*WebhookMatcher      `yaml:"matchers"`
	// Set by Check and prepare.  A router that has been loaded is never changed again; every reload builds new ones.
	tmpl   *template.Template
	client *http.Client
}

// Check validates a router's configuration and compiles its template and regular expressions, so that a mistake rejects
// the router when it is loaded instead of failing, or silently never matching, on every alert.
func (r *WebhookRouter) Check() error {
	if r == nil {
		return errors.New("nil object")
	}
	if r.DestURL == "" {
		return errors.New("missing URL")
	}
	u, err := url.Parse(r.DestURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("URL must be an http:// or https:// address with a host")
	}
	if r.HttpMethod != "" {
		if _, err := http.NewRequest(r.HttpMethod, r.DestURL, nil); err != nil {
			return fmt.Errorf("invalid method: %v", err)
		}
	}
	if r.Template == "" {
		return errors.New("no template")
	}
	tmpl, err := template.New("sendwebhook").Funcs(sprig.FuncMap()).Parse(r.Template)
	if err != nil {
		return fmt.Errorf("template does not parse: %v", err)
	}
	r.tmpl = tmpl
	if len(r.Matchers) < 1 {
		return errors.New("no label matchers")
	}
	for _, m := range r.Matchers {
		if m == nil {
			return errors.New("nil label matcher")
		}
		if m.Label == "" {
			return errors.New("label matcher has no label")
		}
		if m.MatchString == "" && m.MatchRegexp == "" {
			return fmt.Errorf("label matcher for [%s] has neither match nor match_re, so it could never match", m.Label)
		}
		if err := m.compile(); err != nil {
			return fmt.Errorf("label matcher [%s] has an invalid match_re: %v", m, err)
		}
	}
	if r.Authentication == nil {
		r.Authentication = &WebhookAuthentication{}
	}
	return r.Authentication.check()
}

// clone copies a router's configuration into a new router that has not been through Check or prepare
func (r *WebhookRouter) clone() *WebhookRouter {
	if r == nil {
		return nil
	}
	c := &WebhookRouter{
		DestURL:     r.DestURL,
		HttpMethod:  r.HttpMethod,
		Template:    r.Template,
		ContentType: r.ContentType,
	}
	if r.Authentication != nil {
		auth := *r.Authentication
		auth.Cookies = maps.Clone(auth.Cookies)
		c.Authentication = &auth
	}
	if r.TLS != nil {
		tlsConfig := *r.TLS
		c.TLS = &tlsConfig
	}
	for _, m := range r.Matchers {
		if m == nil {
			c.Matchers = append(c.Matchers, nil)
			continue
		}
		c.Matchers = append(c.Matchers, &WebhookMatcher{Label: m.Label, MatchString: m.MatchString, MatchRegexp: m.MatchRegexp})
	}
	return c
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

// check refuses settings that used to be resolved by silently preferring one, or by sending no credentials at all
func (wa *WebhookAuthentication) check() error {
	methods := 0
	if wa.BearerToken != "" {
		methods++
	}
	if wa.BearerTokenFromFile != "" {
		methods++
	}
	if wa.BasicAuth.Username != "" || wa.BasicAuth.Password != "" {
		methods++
	}
	if methods > 1 {
		return errors.New("auth sets more than one of token, tokenFile and basicAuth")
	}
	if wa.BasicAuth.Username == "" && wa.BasicAuth.Password != "" {
		return errors.New("auth.basicAuth has a password but no username")
	}
	return nil
}

// AuthorizationHeader returns the Authorization header to send, or "" for none.  A token file is read every time, so
// a token that is rotated on disk (a projected Kubernetes service account token, say) is picked up without a reload.
func (wa *WebhookAuthentication) AuthorizationHeader() (string, error) {
	if wa.BearerTokenFromFile != "" {
		contents, err := os.ReadFile(wa.BearerTokenFromFile)
		if err != nil {
			return "", fmt.Errorf("reading auth.tokenFile: %w", err)
		}
		// Token files usually end in a newline, which is not valid in a header value
		token := strings.TrimSpace(string(contents))
		if token == "" {
			return "", fmt.Errorf("auth.tokenFile %s is empty", wa.BearerTokenFromFile)
		}
		return "Bearer " + token, nil
	}
	if wa.BearerToken != "" {
		return "Bearer " + wa.BearerToken, nil
	}
	if wa.BasicAuth.Username != "" {
		return wa.BasicAuth.AuthorizationHeader(), nil
	}
	return "", nil
}

// webhookClientTimeout bounds each outbound webhook, including reading the response.  Routers are sent to one after
// another while Alertmanager waits, so an unresponsive destination must not hold up the rest indefinitely.
const webhookClientTimeout = 30 * time.Second

// WebhookTLS controls how a router verifies its destination's certificate.  Without it, the system roots are used.
type WebhookTLS struct {
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify,omitempty"`
	CAFile             string `yaml:"caFile,omitempty"`
}

// HTTPClient builds the client a router sends its webhooks with.  A nil WebhookTLS verifies against the system roots.
func (wt *WebhookTLS) HTTPClient() (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Webhooks have always gone direct; keep ignoring HTTP_PROXY/HTTPS_PROXY
	transport.Proxy = nil
	if wt != nil {
		tlsConfig := &tls.Config{InsecureSkipVerify: wt.InsecureSkipVerify}
		if wt.CAFile != "" {
			caPEM, err := os.ReadFile(wt.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading tls.caFile: %w", err)
			}
			// Like Prometheus' ca_file, the CA replaces the system roots rather than adding to them
			tlsConfig.RootCAs = x509.NewCertPool()
			if !tlsConfig.RootCAs.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("tls.caFile %s contains no PEM certificates", wt.CAFile)
			}
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &http.Client{Transport: transport, Timeout: webhookClientTimeout}, nil
}

// prepare applies a router's defaults and resolves what it needs to send webhooks: its credentials and HTTP client.
func (r *WebhookRouter) prepare() error {
	if r.HttpMethod == "" {
		r.HttpMethod = "POST"
	}
	if r.ContentType == "" {
		r.ContentType = "application/yaml"
	}
	// A token file that cannot be read now would fail every send; reject the router while someone is looking
	if _, err := r.Authentication.AuthorizationHeader(); err != nil {
		return err
	}
	client, err := r.TLS.HTTPClient()
	if err != nil {
		return err
	}
	r.client = client
	if r.TLS != nil && r.TLS.InsecureSkipVerify {
		warnf("Router [URL=\"%s\"] does not verify its destination's TLS certificate (tls.insecureSkipVerify)", r.DestURL)
	}
	return nil
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
		if l == nil {
			continue
		}
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

// compile parses MatchRegexp once; WebhookRouter.Check calls it so routers are fully compiled before they handle alerts
func (m *WebhookMatcher) compile() error {
	if m.MatchRegexp == "" || m.compiledRegexp != nil {
		return nil
	}
	rcomp, err := regexp.Compile(m.MatchRegexp)
	if err != nil {
		return err
	}
	m.compiledRegexp = rcomp
	return nil
}

func (m *WebhookMatcher) doesRegexpMatch(re string) bool {
	if m == nil || m.MatchRegexp == "" {
		return false
	}
	// Normally a no-op since Check() already compiled it; covers matchers that never went through Check()
	if err := m.compile(); err != nil {
		warnf("Error compiling regexp for regular expression [%s]: %v\n", m.MatchRegexp, err)
		return false
	}

	return m.compiledRegexp.MatchString(re)
}

func matcherListContains(sl []*WebhookMatcher, m *WebhookMatcher) bool {
	for _, s := range sl {
		if s == m {
			return true
		}
	}
	return false
}

// IsMatchingAlert reports whether every one of the router's matchers is satisfied, either by the CommonLabels (matchedCommon) or by the alert's own labels
func (r *WebhookRouter) IsMatchingAlert(l *alerts.AlertmanagerAlertV4, matchedCommon []*WebhookMatcher) bool {
	if r == nil {
		warnf("WebhookRouter.IsMatchingAlert error - called with nil WebhookRouter")
		return false
	}
	if l == nil {
		warnf("WebhookRouter.IsMatchingAlert error - called with nil Alert")
		return false
	}

	matchCount := 0
	for _, matcher := range r.Matchers {
		if matcherListContains(matchedCommon, matcher) {
			// Already satisfied this one with the CommonLabels so we count it towards the total # of matched labels
			matchCount++
			continue
		}
		for k, v := range l.Labels {
			if matcher.IsMatch(k, v) {
				// Count each matcher at most once
				matchCount++
				break
			}
		}
	}

	return matchCount == len(r.Matchers)
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

	// Track which matchers the CommonLabels satisfy, rather than which labels matched; two matchers on the same label must each be satisfied
	var commonMatched []*WebhookMatcher
	for _, matcher := range r.Matchers {
		for k, v := range a.CommonLabels {
			if matcher.IsMatch(k, v) {
				commonMatched = append(commonMatched, matcher)
				break
			}
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
	// The group's status may have come from alerts this router does not receive
	tmpAlert.Status = statusOf(subsetAlerts, tmpAlert.Status)

	return tmpAlert, nil
}

// statusOf works out a status for a filtered list of alerts the way Alertmanager does for a group: firing if any alert
// is firing, resolved if all are resolved.  Anything else keeps the fallback.
func statusOf(list []*alerts.AlertmanagerAlertV4, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	for _, al := range list {
		switch al.Status {
		case "firing":
			return "firing"
		case "resolved":
		default:
			return fallback
		}
	}
	return "resolved"
}

// Operational function to execute the router's template and submit the webhook to its destination
func (r *WebhookRouter) SendWebhook(a *alerts.AlertmanagerWebhookTemplateV4) error {
	if r.tmpl == nil || r.client == nil {
		warnf("WebhookRouter.SendWebhook error - router [URL=\"%s\"] was not loaded through Check and prepare", r.DestURL)
		return errors.New("WebhookRouter.SendWebhook error - router was not prepared and has no template or HTTP client")
	}

	b := &bytes.Buffer{}
	b.Grow(len(r.Template)) // Not exact but hopefully accurate enough to reduce the # of memory reallocations
	if err := r.tmpl.Execute(b, a); err != nil {
		warnf("WebhookRouter.SendWebhook failed to execute template for URL=%s: %v", r.DestURL, err)
		tracef("WebhookRouter.SendWebhook template data was [%#v]", a)
		return fmt.Errorf("WebhookRouter.SendWebhook template Execute error %v", err)
	}
	if logEnabled(logLevelTrace) {
		tracef("WebhookRouter.SendWebhook- Trace dumping template output:\n---\n%s\n---\n", b.String())
	}

	req, err := http.NewRequest(r.HttpMethod, r.DestURL, b)
	if err != nil {
		warnf("WebhookRouter.SendWebhook error - cannot create an HTTP Request object for reason [%v]", err)
		return fmt.Errorf("WebhookRouter.SendWebhook http.NewRequest error %v", err)
	}

	// Configure request parameters - content-type, cookies and/or bearer token or basic auth
	req.Header.Set("Content-Type", r.ContentType)
	authHeader, err := r.Authentication.AuthorizationHeader()
	if err != nil {
		warnf("WebhookRouter.SendWebhook error - no credentials for URL=%s: %v", r.DestURL, err)
		return fmt.Errorf("WebhookRouter.SendWebhook credentials error: %w", err)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	for k, v := range r.Authentication.Cookies {
		req.AddCookie(&http.Cookie{
			Name:  k,
			Value: v,
		})
	}

	// Submit HTTP/HTTPS request
	resp, err := r.client.Do(req)
	if err != nil {
		warnf("WebhookRouter.SendWebhook error submitting HTTP request: %v", err)
		return fmt.Errorf("WebhookRouter.SendWebhook error submitting HTTP request: %w", err)
	}
	defer func() {
		// Drain the body so the connection goes back into the router's pool for the next webhook
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		respData = []byte(fmt.Sprintf("(not available due to error [%v])", err))
	}

	// Any 2xx means the destination accepted the webhook; plenty of APIs answer 201 Created, 202 Accepted or 204 No Content
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		warnf("WebhookRouter.SendWebhook failed: destination returned HTTP %s; URL=%s; method=%s; response=%s", resp.Status, r.DestURL, r.HttpMethod, logExcerpt(respData))
		tracef("WebhookRouter.SendWebhook failed: full response from URL=%s:\n%s", r.DestURL, respData)
		return fmt.Errorf("WebhookRouter.SendWebhook destination %s returned HTTP %s", r.DestURL, resp.Status)
	}

	// Successful send
	webhookreqSuccessfulMutex.Lock()
	webhookreqSuccessfulCounter.Inc()
	webhookreqSuccessfulMutex.Unlock()

	tracef("WebhookRouter.SendWebhook successful send: URL=%s; method=%s; status=%s; response=%s", r.DestURL, r.HttpMethod, resp.Status, respData)
	return nil
}

// Webhook server

type WebhookServer struct {
	Listen                    *WebhookServerListen  `yaml:"listen,omitempty"`
	AlertmanagerURL           string                `yaml:"alertmanagerURL"`
	PrometheusURL             string                `yaml:"prometheusURL"`
	Routers                   []*WebhookRouter      `yaml:"routers,omitempty"`
	AdditionalRouterDirectory string                `yaml:"addlRouterDir,omitempty"`
	AdditionalRouterWatch     time.Duration         `yaml:"addlRouterDirWatchInterval,omitempty"`
	ReloadTriggerFile         string                `yaml:"reloadTriggerFile,omitempty"`
	Metrics                   *WebhookServerMetrics `yaml:"metrics,omitempty"`
	LogLevel                  string                `yaml:"logLevel,omitempty"`
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

// SIGHUP, the trigger file and the directory watcher can all ask for a reload at once; they take turns
var reloadMutex sync.Mutex

// ReloadRouters builds a new set of routers from the config file's routers and the additional router directory, and
// swaps it in.  Requests that are being served keep the set they started with.
func (w *WebhookServer) ReloadRouters() error {
	reloadMutex.Lock()
	defer reloadMutex.Unlock()

	var loaded []*WebhookRouter
	rejected := 0
	accept := func(rt *WebhookRouter, source string) {
		if rt == nil {
			rejected++
			warnf("Rejecting router from %s: it is empty", source)
			return
		}
		err := rt.Check()
		if err == nil {
			err = rt.prepare()
		}
		if err != nil {
			rejected++
			warnf("Rejecting router [URL=\"%s\"] from %s: %v", rt.DestURL, source, err)
			return
		}
		loaded = append(loaded, rt)
		debugf("Including router: [URL=\"%s\"|Method=%s|ContentType=\"%s\"|%d matchers]", rt.DestURL, rt.HttpMethod, rt.ContentType, len(rt.Matchers))
	}

	// The configured routers are only ever copied, so a reload cannot disturb the ones that are handling requests
	for i, rt := range w.Routers {
		accept(rt.clone(), fmt.Sprintf("the config file (router %d)", i+1))
	}

	if w.AdditionalRouterDirectory != "" {
		debugf("Inspecting AdditionalRouterDirectory [%s] for more routers", w.AdditionalRouterDirectory)
		files, err := os.ReadDir(w.AdditionalRouterDirectory)
		if err != nil {
			warnf("Error reading router configs from directory [%s]: %v", w.AdditionalRouterDirectory, err)
		}
		for _, file := range files {
			path := filepath.Join(w.AdditionalRouterDirectory, file.Name())
			// Stat follows symlinks: a ConfigMap or Secret volume holds a "..data" link to a directory next to its files
			if info, err := os.Stat(path); err != nil || info.IsDir() {
				tracef("Directory entry is not a file: %s", file.Name())
				continue
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				rejected++
				warnf("Rejecting router file [%s]: %v", file.Name(), err)
				continue
			}
			rt := new(WebhookRouter)
			dec := yaml.NewDecoder(bytes.NewReader(contents))
			// A misspelled key must not quietly leave a router without its credentials or TLS settings
			dec.SetStrict(true)
			if err := dec.Decode(rt); err != nil {
				rejected++
				warnf("Rejecting router file [%s]: not a router document: %v", file.Name(), err)
				continue
			}
			accept(rt, "file "+file.Name())
		}
	}

	if len(loaded) < 1 {
		return errors.New("WebhookServer.ReloadRouters error - No valid routers present")
	}

	routerMutex.Lock()
	routersRejected = rejected
	w.allRouters = loaded
	routerMutex.Unlock()

	infof("Loaded %d routers; rejected %d", len(loaded), rejected)
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
	var addlRouterDirSum string
	if w.AdditionalRouterDirectory != "" && w.AdditionalRouterWatch > 0 {
		// Fingerprint before the initial load so a change landing mid-load still triggers a reload
		addlRouterDirSum = routerDirChecksum(w.AdditionalRouterDirectory)
	}
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
	tracef("Registered Prometheus metric: %s_webhook_routers", ApplicationName)

	rejectedRouters = promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_routers_rejected",
		Help: "This is the number of webhook router configs viewed - either in app config or found as valid routers in the additional router config directory - and determined unworkable",
	})
	rejectedRouters.Set(float64(routersRejected))
	tracef("Registered Prometheus metric: %s_webhook_routers_rejected", ApplicationName)

	// connectionMutex, connectionGauge defined further below near the main API handler function
	connectionGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: ApplicationName + "_webhook_connections",
		Help: "Number of active connections to the webhook router (active connections from an Alertmanager)",
	})
	connectionGauge.Set(0)
	tracef("Registered Prometheus metric: %s_webhook_connections", ApplicationName)

	connectionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests",
		Help: "Total number of webhook requests seen",
	})
	prometheus.MustRegister(connectionCounter)
	tracef("Registered Prometheus metric: %s_webhook_requests", ApplicationName)

	healthzCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_healthz_count",
		Help: "Total number of /healthz health check requests",
	})
	prometheus.MustRegister(healthzCounter)
	tracef("Registered Prometheus metric: %s_healthz_count", ApplicationName)

	// webhookreq* mutex and prometheus metric variables defined further below near main API handler function
	webhookreqAttemptedCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests_attempted",
		Help: "Number of webhook requests received by Alertmanager where a router was matched and attempted",
	})
	prometheus.MustRegister(webhookreqAttemptedCounter)
	tracef("Registered Prometheus metric: %s_webhook_requests_attempted", ApplicationName)

	webhookreqSuccessfulCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: ApplicationName + "_webhook_requests_successful",
		Help: "Number of webhook requests received by Alertmanager where a router was matched and successfully routed (destination answered with a 2xx status)",
	})
	prometheus.MustRegister(webhookreqSuccessfulCounter)
	tracef("Registered Prometheus metric: %s_webhook_requests_successful", ApplicationName)

	// Set up SIGHUP handler for reloading routers
	hupChan := make(chan os.Signal, 4)
	go func(hupchan chan os.Signal, w *WebhookServer) {
		for {
			<-hupchan
			infof("SIGHUP received")
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
	infof("Listening for SIGHUP to reload the router list")

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
		infof("Watching every 5 seconds for trigger file [%s] to reload the router list", w.ReloadTriggerFile)
	}

	// Set up AdditionalRouterDirectory watcher for reloading routers when the directory contents change.
	// This lets a Kubernetes ConfigMap/Secret volume be updated in place without a sidecar touching the ReloadTriggerFile.
	if w.AdditionalRouterDirectory != "" && w.AdditionalRouterWatch > 0 {
		go func(lastSum string, w *WebhookServer) {
			for {
				time.Sleep(w.AdditionalRouterWatch)
				sum := routerDirChecksum(w.AdditionalRouterDirectory)
				if sum == lastSum {
					continue
				}
				lastSum = sum
				infof("Contents of AdditionalRouterDirectory [%s] changed; reloading routers", w.AdditionalRouterDirectory)
				err := w.ReloadRouters()
				if err != nil {
					// True to the same behavior as .Start(), if there are no routers defined, we bomb.
					panic("Router directory change-initiated router reload ended in error: " + err.Error())
				}
				routerMutex.Lock()
				rejectedRouters.Set(float64(routersRejected))
				routerMutex.Unlock()
			}
		}(addlRouterDirSum, w)
		infof("Watching every %s for changes in AdditionalRouterDirectory [%s] to reload the router list", w.AdditionalRouterWatch, w.AdditionalRouterDirectory)
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
	infof("WebhookServer listening on: %s\n", listenStr)
	debugf("All URIs: %#v\n", allURIs)
	log.Fatal(http.ListenAndServe(listenStr, nil))
	return nil
}

// routerDirChecksum fingerprints the files ReloadRouters would read from dir.  Symlinks are followed, so the atomic
// ..data symlink swap Kubernetes performs when updating a ConfigMap/Secret volume shows up as a change.
func routerDirChecksum(dir string) string {
	files, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	h := sha256.New()
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			continue
		}
		fmt.Fprintf(h, "%s\x00%d\x00", file.Name(), len(contents))
		h.Write(contents)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (w *WebhookServer) GetRouters() []*WebhookRouter {
	// ReloadRouters swaps allRouters under routerMutex while requests are being served
	routerMutex.Lock()
	defer routerMutex.Unlock()
	return w.allRouters
}

// HealthZ for readiness probes
var healthzMutex sync.Mutex
var healthzCounter prometheus.Counter

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	healthzMutex.Lock()
	healthzCounter.Inc()
	healthzMutex.Unlock()

	if ENABLE_HEALTHZ_DEBUG {
		tracef("Received healthz request [%#v]", r)
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
		debugf("Received HTTP request with invalid method [%s] - expecting POST", r.Method)
		fmt.Fprintf(w, "Invalid request method [%s] - we only expect the use of POST with this endpoint\r\n", r.Method)
		return
	}

	// Collect payload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		warnf("Error reading request body [%v]", err)
		fmt.Fprintf(w, "Error reading request body [%v]\r\n", err)
		return
	}
	defer r.Body.Close()

	tracef("Received a POST payload:\nHeaders: %#v\nPostdata:\n%s\n", r.Header, body)

	// Alertmanager sends JSON.  Decoding it as anything looser would refuse or alter text that JSON carries untouched.
	alertwebhook := new(alerts.AlertmanagerWebhookInputV4)
	if err := json.Unmarshal(body, alertwebhook); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error processing webhook from POST data [%v]\r\n", err)
		warnf("Refusing a webhook: POST data is not an Alertmanager webhook in JSON: %v", err)
		return
	}
	// Nothing can be routed from a payload we do not understand, so do not tell Alertmanager it was delivered
	if alertwebhook.Version != alerts.WebhookVersion {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Unsupported webhook version [%s] - this endpoint expects version %s\r\n", alertwebhook.Version, alerts.WebhookVersion)
		warnf("Refusing a webhook: version is [%s], expected [%s]", alertwebhook.Version, alerts.WebhookVersion)
		return
	}
	// A null in the alert list carries nothing to route
	alertwebhook.Alerts = slices.DeleteFunc(alertwebhook.Alerts, func(al *alerts.AlertmanagerAlertV4) bool { return al == nil })

	if logEnabled(logLevelTrace) {
		tracef("Received the following alert webhook:\n%s\n", alertwebhook.String())
	}

	routers := GlobalWebhookServer.GetRouters()
	tracef("Processing through %d routers-", len(routers))
	for _, router := range routers {
		routeWebhook(router, alertwebhook)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("\r\n"))
}

// routeWebhook sends the webhook through one router, if the router wants any of it
func routeWebhook(r *WebhookRouter, a *alerts.AlertmanagerWebhookInputV4) {
	// Whatever goes wrong with one router, the routers after it still get the alert
	defer func() {
		if p := recover(); p != nil {
			warnf("Router [URL=\"%s\"] panicked while handling a webhook: %v\n%s", r.DestURL, p, debug.Stack())
		}
	}()

	// Cheap first pass: every matcher must find something somewhere in the group
	for _, m := range r.Matchers {
		if !m.HasMatchingAlerts(a) {
			tracef("router [URL=\"%s\"] skipped: nothing matches %s", r.DestURL, m)
			return
		}
	}

	templated, err := r.PrepareTemplateData(a)
	if err != nil {
		warnf("Attempted to route a webhook to [URL=\"%s\"] but failed: %v", r.DestURL, err)
		return
	}
	// The matchers were satisfied by different alerts and no single alert satisfies them all
	if len(templated.Alerts) == 0 && len(a.Alerts) > 0 {
		tracef("router [URL=\"%s\"] skipped: no alert satisfies every matcher", r.DestURL)
		return
	}

	webhookreqAttemptedMutex.Lock()
	webhookreqAttemptedCounter.Inc()
	webhookreqAttemptedMutex.Unlock()

	// SendWebhook reports its own failures
	r.SendWebhook(templated)
}
