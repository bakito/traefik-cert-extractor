package cert

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/grantae/certinfo"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const (
	end = "-----END CERTIFICATE-----"
)

// WatchFileChanges watch acme file changes and update the certs
func WatchFileChanges(log *zap.SugaredLogger, acmePath string, certsDir string) {

	if err := Extract(log, acmePath, certsDir); err != nil {
		log.Fatal(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					log.Infow("modified file", "name", event.Name)
					time.Sleep(time.Second)
					if err := Extract(log, event.Name, certsDir); err != nil {
						log.Error(err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Error(err)
			}
		}
	}()

	err = watcher.Add(acmePath)
	if err != nil {
		log.Fatal(err)
	}
	<-done
}

// Extract the certs from the acme file
func Extract(log *zap.SugaredLogger, acmePath string, certsDir string) error {
	dat, err := ioutil.ReadFile(acmePath)
	if err != nil {
		return err
	}
	acme := &Acme{}
	if err := json.Unmarshal(dat, acme); err != nil {
		return err
	}

	for _, r := range *acme {
		for _, c := range r.Certificates {
			log.Infow("extracting certs", "domain", c.Domain.Main)
			dir := filepath.Join(certsDir, c.Domain.Main)
			err = os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return err
			}
			var fullChain []byte
			if fullChain, err = writeCert(filepath.Join(dir, "fullchain.pem"), c.Certificate); err != nil {
				return err
			}

			cert, chain := splitCert(fullChain)
			err = ioutil.WriteFile(filepath.Join(dir, "cert.pem"), cert, 0644)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(filepath.Join(dir, "chain.pem"), chain, 0644)
			if err != nil {
				return err
			}

			info, err := info(cert)
			if err == nil {
				err = ioutil.WriteFile(filepath.Join(dir, "info"), []byte(info), 0644)
				if err != nil {
					return err
				}
			}
			if err != nil {
				return err
			}
			if _, err := writeCert(filepath.Join(dir, "privkey.pem"), c.Key); err != nil {
				return err
			}
		}
	}

	return nil
}

func splitCert(fullChain []byte) ([]byte, []byte) {
	var cert []string
	var chain []string
	certDone := false

	for _, l := range strings.Split(string(fullChain), "\n") {
		if strings.TrimSpace(l) != "" {
			if !certDone {
				cert = append(cert, l)
				certDone = end == strings.TrimSpace(l)
			} else {
				chain = append(chain, l)
			}
		}
	}
	return []byte(strings.Join(cert, "\n")), []byte(strings.Join(chain, "\n"))
}

func info(cert []byte) (string, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return "", errors.New("error decoding cert")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	return certinfo.CertificateText(c)
}

func writeCert(path string, data string) ([]byte, error) {
	cert, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(path, cert, 0644)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
