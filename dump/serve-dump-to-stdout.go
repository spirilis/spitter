// This implements a generic webserver that receives requests and dumps them to stdout.

package dump

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TODO: Implement a better debug log system
const DEBUGLEVEL_TRACE = true
const DEBUGLEVEL_DEBUG = true
const DEBUGLEVEL_INFO = true
const DEBUGLEVEL_WARNING = true

type ServerDump struct {
	Listen          string `yaml:"host,omitempty"`
	Port            int    `yaml:"port,omitempty"`
	ApplicationName string // Used for Prometheus metrics names
}

var connectionCountMutex sync.Mutex
var connectionCounter prometheus.Counter

var healthzMutex sync.Mutex
var healthzCounter prometheus.Counter

func (s *ServerDump) Start() error {
	if s.Listen == "" {
		if DEBUGLEVEL_TRACE {
			log.Println("No Listen string provided; using default of 0.0.0.0")
		}
		s.Listen = "0.0.0.0"
	}
	if s.Port < 1 {
		if DEBUGLEVEL_TRACE {
			log.Println("No Port provided; using default of 9880")
		}
		s.Port = 9880
	}

	// Set up prometheus metrics
	connectionCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: s.ApplicationName + "_serverdump_webhook_requests",
		Help: "Total number of HTTP requests seen",
	})
	prometheus.MustRegister(connectionCounter)
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_serverdump_webhook_requests", s.ApplicationName)
	}

	healthzCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name: s.ApplicationName + "_serverdump_healthz_count",
		Help: "Total number of /healthz health check requests",
	})
	prometheus.MustRegister(healthzCounter)
	if DEBUGLEVEL_TRACE {
		log.Printf("Registered Prometheus metric: %s_serverdump_healthz_count", s.ApplicationName)
	}

	// Set up HTTP handlers
	var allURIs []string

	http.HandleFunc("/healthz", handleHealthz)
	allURIs = append(allURIs, "/healthz")

	http.Handle("/metrics", promhttp.Handler())
	allURIs = append(allURIs, "/metrics")

	http.HandleFunc("/dump", handleDump)
	allURIs = append(allURIs, "/dump")

	listenStr := fmt.Sprintf("%s:%d", s.Listen, s.Port)
	log.Printf("ServerDump listening on: %s\n", listenStr)
	if DEBUGLEVEL_DEBUG {
		log.Printf("All URIs: %#v\n", allURIs)
	}
	log.Fatal(http.ListenAndServe(listenStr, nil))
	return nil
}

func handleHealthz(w http.ResponseWriter, r *http.Request) {
	healthzMutex.Lock()
	healthzCounter.Inc()
	healthzMutex.Unlock()

	if DEBUGLEVEL_TRACE {
		log.Printf("Received healthz request [%#v]", r)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Up\n"))
}

func handleDump(w http.ResponseWriter, r *http.Request) {
	// Handle prometheus metrics here
	connectionCountMutex.Lock()
	connectionCounter.Inc()
	connectionCountMutex.Unlock()

	var out string

	out = fmt.Sprintf("Host: %s\n", r.Host)
	out += fmt.Sprintf("URI: %s\n", r.RequestURI)
	out += "Headers:\n"
	maxlen := 0
	for k := range r.Header {
		if len(k) > maxlen {
			maxlen = len(k)
		}
	}
	for k, v := range r.Header {
		l := len(k)
		out += "  "
		for i := 0; i < (maxlen - l); i++ {
			out += " "
		}
		out += fmt.Sprintf("%s: %s\n", k, v)
	}
	out += "Body:\n"
	b, err := io.ReadAll(r.Body)
	if err != nil {
		out += fmt.Sprintf("<error reading body: %v>\n", err)
	} else {
		out += string(b) + "\n"
	}
	fmt.Println(out)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("\r\n"))
}
