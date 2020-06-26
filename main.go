package main

import (
	"net/http"
	"os"

	"go.uber.org/zap/zapcore"

	"github.com/bakito/traefik-cert-extractor/pkg/cert"
	"go.uber.org/zap"
)

const (
	envCertsDir     = "CERTS_DIR"
	envAcmeFilePath = "ACME_FILE_PATH"
)

func main() {
	log := initLogger()
	defer log.Sync()

	go cert.WatchFileChanges(log, os.Getenv(envAcmeFilePath), os.Getenv(envCertsDir))

	// create file server handler
	fs := http.FileServer(http.Dir(os.Getenv(envCertsDir)))

	// start HTTP server with `fs` as the default handler
	log.Fatal(http.ListenAndServe(":9000", fs))
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
