package main

import (
	"net/http"
	"os"

	"go.uber.org/zap/zapcore"

	"github.com/bakito/traefik-cert-extractor/pkg/cert"
	"go.uber.org/zap"
)

const (
	envAcmeFilePath = "ACME_FILE_PATH"
	envCertsDir     = "CERTS_DIR"
)

var (
	acmePath string
	certsDir string
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

	go cert.WatchFileChanges(log, acmePath, certsDir)

	// create file server handler
	fs := http.FileServer(http.Dir(certsDir))

	// start HTTP server with `fs` as the default handler
	log.Fatal(http.ListenAndServe(":8080", fs))
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
