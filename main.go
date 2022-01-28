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
	"github.com/dyson/certman"
	"github.com/gin-gonic/gin"
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
	gin.SetMode(gin.ReleaseMode)

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

	certs, err := cert.New(log, acmePath, certsDir)
	if err != nil {
		log.Fatal(err)
	}

	go certs.WatchFileChanges()

	r := setupRouter(certs)

	certsDir := "/ssl"
	if d, ok := os.LookupEnv("CERTS_DIR"); ok {
		certsDir = d
	}

	log.Infow("Starting traefik-cert-extractor", "port", addr[1:], "version", version.Version)

	if ownAddress != "" {

		chain := filepath.Join(certsDir, ownAddress, "fullchain.pem")
		key := filepath.Join(certsDir, ownAddress, "privkey.pem")

		// generate a `Certificate` struct
		crt, err := tls.LoadX509KeyPair(chain, key)
		if err != nil {
			log.Fatalw("Error resolving certs", "ownAddress", ownAddress, "certsDir", certsDir, "error", err)
		}

		cm, err := certman.New(chain, key)
		if err != nil {
			log.Fatalw("Error resolving certs", "ownAddress", ownAddress, "certsDir", certsDir, "error", err)
		}
		cm.Logger(&logWrapper{sl: log})
		if err := cm.Watch(); err != nil {
			log.Fatalw("Error watching certs", "ownAddress", ownAddress, "certsDir", certsDir, "error", err)
		}

		// create a custom server with `TLSConfig`
		s := &http.Server{
			Addr:    addr,
			Handler: r,
			TLSConfig: &tls.Config{
				Certificates:   []tls.Certificate{crt},
				MinVersion:     tls.VersionTLS12,
				GetCertificate: cm.GetCertificate,
			},
		}
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		// start HTTP server with `fs` as the default handler
		log.Fatal(http.ListenAndServe(addr, r))
	}
}

func setupRouter(certs cert.Certs) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	index, _ := static.ReadFile("static/index.html")
	r.SetHTMLTemplate(template.Must(template.New("index.html").Parse(string(index))))

	r.GET("/", func(c *gin.Context) {
		data := PageData{
			PageTitle: "Known Certificates",
			Certs:     certs.Certs(),
			Version:   version.Version,
		}
		c.HTML(200, "index.html", data)
	})
	staticFile(r, "/gopher.png")
	staticFile(r, "/favicon.ico")
	staticFile(r, "/style.css")

	r.GET("/:dir/:file", func(c *gin.Context) {
		path := filepath.Join(certsDir, c.Param("dir"), c.Param("file"))
		c.File(path)
	})
	return r
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

func staticFile(r *gin.Engine, file string) {
	r.GET(file, func(c *gin.Context) {
		c.FileFromFS(filepath.Join("static", file), http.FS(static))
	})
}

type logWrapper struct {
	sl *zap.SugaredLogger
}

func (l *logWrapper) Printf(format string, v ...interface{}) {
	l.sl.Infof(format, v...)
}
