package main

import (
	"bytes"
	"log"
	"os"

	"github.com/spirilis/spitter/dump"

	"github.com/alecthomas/kong"
	"gopkg.in/yaml.v2"
)

const ApplicationName = `spitter`

// TODO: Implement a better debug log system
const DEBUGLEVEL_TRACE = true
const DEBUGLEVEL_DEBUG = true
const DEBUGLEVEL_INFO = true
const DEBUGLEVEL_WARNING = true

var CLI struct {
	Router struct {
		Config        string `optional:"" name:"config" help:"Path to config file defining the WebhookServer parameters"`
		Alertmanager  string `optional:"" name:"alertmanager" help:"Accessible URL to the root of the Alertmanager webserver"`
		Prometheus    string `optional:"" name:"prometheus" help:"Accessible URL to the root of the Prometheus webserver"`
		RouterDir     string `optional:"" name:"routers" help:"Directory full of webhook router YAML or JSON configuration documents"`
		ReloadTrigger string `optional:"" name:"reload-trigger" help:"File to watch indicating a reload of router config is necessary; file is deleted after reload.  SIGHUP also performs this."`
	} `cmd:"" help:"Run a webhook router server receiving Alertmanager V4 webhooks"`
	Dump struct {
		Listen string `optional:"" name:"listen" help:"Hostname or IP address of interface to listen"`
		Port   int    `optional:"" name:"port" help:"TCP port for listening"`
	} `cmd:"" help:"Run a simple webserver that dumps its requests to stdout"`
}

func main() {
	ctx := kong.Parse(&CLI)
	switch ctx.Command() {
	case "router":
		configObj := new(WebhookServer)
		if CLI.Router.Config == "" {
			// Bog-standard default configuration
			configObj = &WebhookServer{
				AlertmanagerURL: "http://alertmanager",
				PrometheusURL:   "http://prometheus",
			}
			r := &WebhookRouter{
				DestURL:  "http://destination/webhook",
				Template: "{{ .Status }}\n{{- range .Alerts }}  Status: {{ .Status }}\n{{- end }}\n",
			}
			m := &WebhookMatcher{
				Label:       "test",
				MatchString: "true",
			}
			r.Matchers = append(r.Matchers, m)
			configObj.Routers = append(configObj.Routers, r)
		} else {
			// Read the config file
			cf, err := os.ReadFile(CLI.Router.Config)
			if err != nil {
				log.Fatalf("Error reading Router config file: %v\n", err)
			}
			b := bytes.NewBuffer(cf)
			dec := yaml.NewDecoder(b)
			err = dec.Decode(configObj)
			if err != nil {
				log.Fatalf("Error unmarshalling Router config from file [%s]: %v\n", CLI.Router.Config, err)
			}
		}
		// CLI config option overrides
		if CLI.Router.Alertmanager != "" {
			configObj.AlertmanagerURL = CLI.Router.Alertmanager
		}
		if CLI.Router.Prometheus != "" {
			configObj.PrometheusURL = CLI.Router.Prometheus
		}
		if CLI.Router.RouterDir != "" {
			configObj.AdditionalRouterDirectory = CLI.Router.RouterDir
		}
		if CLI.Router.ReloadTrigger != "" {
			configObj.ReloadTriggerFile = CLI.Router.ReloadTrigger
		}

		// Run the webhook routing server
		err := configObj.Start()
		if err != nil {
			log.Fatalf("WebhookServer returned with error: %v\n", err)
		}
	case "dump":
		dump := &dump.ServerDump{
			Listen:          CLI.Dump.Listen,
			Port:            CLI.Dump.Port,
			ApplicationName: ApplicationName,
		}

		err := dump.Start()
		if err != nil {
			log.Fatalf("ServerDump returned with error: %v\n", err)
		}
	default:
		panic(ctx.Command())
	}
}
