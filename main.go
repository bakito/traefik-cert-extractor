package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"path/filepath"

	"go.uber.org/zap/zapcore"

	"github.com/bakito/traefik-cert-extractor/pkg/cert"
	"go.uber.org/zap"
)

const (
	envAcmeFilePath = "ACME_FILE_PATH"
	envCertsDir     = "CERTS_DIR"
	envOwnAddress   = "OWN_ADDRESS"
)

var (
	acmePath   string
	certsDir   string
	ownAddress string
)

func main() {
	log := initLogger()
	defer log.Sync()

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

	go cert.WatchFileChanges(log, acmePath, certsDir)

	// create file server handler
	fs := http.FileServer(http.Dir(certsDir))

	certsDir := "/ssl"
	if d, ok := os.LookupEnv("CERTS_DIR"); ok {
		certsDir = d
	}

	addr := ":8080"

	if ownAddress != "" {
		// generate a `Certificate` struct
		cert, err := tls.LoadX509KeyPair(filepath.Join(certsDir, ownAddress, "fullchain.pem"), filepath.Join(certsDir, ownAddress, "privkey.pem"))
		if err != nil {
			log.Fatalw("Error resolving certs", "ownAddress", ownAddress, "certsDir", certsDir)
		}

		// create a custom server with `TLSConfig`
		s := &http.Server{
			Addr:    addr,
			Handler: fs,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		log.Fatal(s.ListenAndServeTLS("", ""))
	} else {
		// start HTTP server with `fs` as the default handler
		log.Fatal(http.ListenAndServe(addr, fs))
	}
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
