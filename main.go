package main

import (
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	alog "github.com/apex/log"
	kitlog "github.com/go-kit/log"
	"github.com/jenningsloy318/redfish_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	Version       string
	BuildRevision string
	BuildBranch   string
	BuildTime     string
	BuildHost     string
	rootLoggerCtx *alog.Entry

	configFile = kingpin.Flag(
		"config.file",
		"Path to configuration file.",
	).String()
	webConfig   = webflag.AddFlags(kingpin.CommandLine)
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address to listen on for web interface and telemetry.",
	).Default(":9610").String()
	sc = &SafeConfig{
		C: &HostConfig{},
	}
	reloadCh chan chan error
)

func init() {
	rootLoggerCtx = alog.WithFields(alog.Fields{
		"app": "redfish_exporter",
	})

	hostname, _ := os.Hostname()
	rootLoggerCtx.Infof("version %s, build reversion %s, build branch %s, build at %s on host %s", Version, BuildRevision, BuildBranch, BuildTime, hostname)
}

func reloadHandler(configLoggerCtx *alog.Entry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" || r.Method == "PUT" {
			configLoggerCtx.Info("Triggered configuration reload from /-/reload HTTP endpoint")
			err := sc.ReloadConfig(*configFile)
			if err != nil {
				configLoggerCtx.WithError(err).Error("failed to reload config file")
				http.Error(w, "failed to reload config file", http.StatusInternalServerError)
			}
			configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file reloaded")

			w.WriteHeader(http.StatusOK)
			io.WriteString(w, "Configuration reloaded successfully!")
		} else {
			http.Error(w, "Only PUT and POST methods are allowed", http.StatusBadRequest)
		}
	}
}

// define new http handleer
func metricsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		registry := prometheus.NewRegistry()
		
		var (
			hostConfig *HostConfig
			err        error
		)
		targetLoggerCtx := rootLoggerCtx
		targetLoggerCtx.Info("scraping target host")
		
		// Always falling back to single host config when group config failed.
		if hostConfig, err = sc.HostConfig(); err != nil {
			targetLoggerCtx.WithError(err).Error("error getting credentials")
			return
		}
		
		

		collector := collector.NewRedfishCollector(hostConfig.Host, hostConfig.Username, hostConfig.Password, targetLoggerCtx)
		registry.MustRegister(collector)
		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)

	}
}

func main() {
	log.AddFlags(kingpin.CommandLine)
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	kitlogger := kitlog.NewLogfmtLogger(os.Stderr)

	configLoggerCtx := rootLoggerCtx.WithField("config", *configFile)
	configLoggerCtx.Info("starting app")
	// load config  first time
	if err := sc.ReloadConfig(*configFile); err != nil {
		configLoggerCtx.WithError(err).Error("error parsing config file")
		panic(err)
	}

	configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file loaded")

	// load config in background to watch for config changes
	hup := make(chan os.Signal)
	reloadCh = make(chan chan error)
	signal.Notify(hup, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-hup:
				if err := sc.ReloadConfig(*configFile); err != nil {
					configLoggerCtx.WithError(err).Error("failed to reload config file")
					break
				}
				configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file reload")
			case rc := <-reloadCh:
				if err := sc.ReloadConfig(*configFile); err != nil {
					configLoggerCtx.WithError(err).Error("failed to reload config file")
					rc <- err
					break
				}
				configLoggerCtx.WithField("operation", "sc.ReloadConfig").Info("config file reloaded")
				rc <- nil
			}
		}
	}()

	http.Handle("/redfish", metricsHandler())                // Regular metrics endpoint for local Redfish metrics.
	http.Handle("/-/reload", reloadHandler(configLoggerCtx)) // HTTP endpoint for triggering configuration reload
	http.Handle("/metrics", promhttp.Handler())

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head>
            <title>Redfish Exporter</title>
            </head>
						<body>
            <h1>redfish Exporter</h1>
						<p><a href="/redfish">Redfish metrics</a></p>
						<p><a href="/metrics">Local metrics</a></p>
            </body>
            </html>`))
	})

	rootLoggerCtx.Infof("app started. listening on %s", *listenAddress)
	srv := &http.Server{Addr: *listenAddress}
	err := web.ListenAndServe(srv, *webConfig, kitlogger)
	if err != nil {
		log.Fatal(err)
	}
}
