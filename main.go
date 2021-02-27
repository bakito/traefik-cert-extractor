package main

import (
	"crypto/tls"
	"embed"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"github.com/bakito/traefik-cert-extractor/pkg/cert"
	"github.com/bakito/traefik-cert-extractor/version"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	envAcmeFilePath = "ACME_FILE_PATH"
	envCertsDir     = "CERTS_DIR"
	envOwnAddress   = "OWN_ADDRESS"
	addr            = ":8080"
)

var (
	acmePath   string
	certsDir   string
	ownAddress string
	//go:embed static/*
	static embed.FS
)

func main() {
	log := initLogger()
	defer func() { _ = log.Sync() }()

	if e, ok := os.LookupEnv(envAcmeFilePath); !ok {
		log.Fatalw("Missing environment variable", "name", envAcmeFilePath)
	} else {
		acmePath = e
	}

	if e, ok := os.LookupEnv(envCertsDir); !ok {
		log.Fatalw("Missing environment variable", "name", envCertsDir)
	} else {
		certsDir = e
	}

	if e, ok := os.LookupEnv(envOwnAddress); ok {
		ownAddress = e
	}

	certs := cert.Certs{}

	go certs.WatchFileChanges(log, acmePath, certsDir)

	r := mux.NewRouter()

	r.PathPrefix("/{category}/").Handler(http.FileServer(http.Dir(certsDir)))
	index, _ := static.ReadFile("static/index.html")
	tmpl := template.Must(template.New("layout.html").Parse(string(index)))

	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := PageData{
			PageTitle: "Known Certificates",
			Certs:     certs.Certs(),
			Version:   version.Version,
		}
		_ = tmpl.Execute(w, data)
	})
	fromBox(r, "/gopher.png")
	fromBox(r, "/favicon.ico")
	fromBox(r, "/style.css")

	certsDir := "/ssl"
	if d, ok := os.LookupEnv("CERTS_DIR"); ok {
		certsDir = d
	}

	log.Infow("Starting traefik-cert-extractor", "port", addr[1:], "version", version.Version)

	if ownAddress != "" {
		// generate a `Certificate` struct
		crt, err := tls.LoadX509KeyPair(filepath.Join(certsDir, ownAddress, "fullchain.pem"), filepath.Join(certsDir, ownAddress, "privkey.pem"))
		if err != nil {
			log.Fatalw("Error resolving certs", "ownAddress", ownAddress, "certsDir", certsDir)
		}

		// create a custom server with `TLSConfig`
		s := &http.Server{
			Addr:    addr,
			Handler: r,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{crt},
			},
		}
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		// start HTTP server with `fs` as the default handler
		log.Fatal(http.ListenAndServe(addr, r))
	}
}

// PageData page rendering data
type PageData struct {
	PageTitle string
	Certs     []cert.Cert
	Version   string
}

func initLogger() *zap.SugaredLogger {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logger, _ := zap.Config{
		Encoding:      "json",
		Level:         zap.NewAtomicLevelAt(zapcore.DebugLevel),
		OutputPaths:   []string{"stdout"},
		EncoderConfig: encoderConfig,
	}.Build()

	return logger.Sugar()
}

func fromBox(r *mux.Router, file string) {
	r.HandleFunc(file, func(w http.ResponseWriter, r *http.Request) {
		f, _ := static.ReadFile(filepath.Join("static", file))
		_, _ = w.Write(f)
	})
}
