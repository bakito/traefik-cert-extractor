package cert

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/grantae/certinfo"
	"go.uber.org/zap"
)

const (
	end = "-----END CERTIFICATE-----"
)

// Certs all certificates
type Certs struct {
	certs map[string]Cert
}

// Cert a certificate
type Cert struct {
	Name      string
	NotBefore time.Time
	NotAfter  time.Time
}

// NotBeforeString NotBefore as string
func (c *Cert) NotBeforeString() string {
	return c.NotBefore.Format("02.01.2006")
}

// NotAfterString NotAfter as string
func (c *Cert) NotAfterString() string {
	return c.NotAfter.Format("02.01.2006")
}

// Certs get the current certs
func (c *Certs) Certs() []Cert {
	var certs []Cert

	for _, value := range c.certs {
		certs = append(certs, value)
	}
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].Name > certs[j].Name
	})

	return certs
}

// WatchFileChanges watch acme file changes and update the certs
func (c *Certs) WatchFileChanges(log *zap.SugaredLogger, acmePath string, certsDir string) {
	c.certs = make(map[string]Cert)

	if err := c.extract(log, acmePath, certsDir); err != nil {
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
					if err := c.extract(log, event.Name, certsDir); err != nil {
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

func (c *Certs) extract(log *zap.SugaredLogger, acmePath string, certsDir string) error {
	dat, err := ioutil.ReadFile(acmePath)
	if err != nil {
		return err
	}
	acme := &Acme{}
	if err := json.Unmarshal(dat, acme); err != nil {
		return err
	}

	for _, r := range *acme {
		for _, crt := range r.Certificates {
			log.Infow("extracting certs", "domain", crt.Domain.Main)
			dir := filepath.Join(certsDir, crt.Domain.Main)
			err = os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return err
			}
			var fullChain []byte
			if fullChain, err = c.writeCert(filepath.Join(dir, "fullchain.pem"), crt.Certificate); err != nil {
				return err
			}

			cert, chain := c.splitCert(fullChain)
			err = ioutil.WriteFile(filepath.Join(dir, "cert.pem"), cert, 0644)
			if err != nil {
				return err
			}
			err = ioutil.WriteFile(filepath.Join(dir, "chain.pem"), chain, 0644)
			if err != nil {
				return err
			}

			info, infoCrt, err := c.info(cert)
			if err == nil {
				err = ioutil.WriteFile(filepath.Join(dir, "info"), []byte(info), 0644)
				if err != nil {
					return err
				}
			}
			if err != nil {
				return err
			}
			if _, err := c.writeCert(filepath.Join(dir, "privkey.pem"), crt.Key); err != nil {
				return err
			}
			c.certs[crt.Domain.Main] = Cert{
				Name:      crt.Domain.Main,
				NotBefore: infoCrt.NotBefore,
				NotAfter:  infoCrt.NotAfter,
			}
		}
	}

	return nil
}

func (c *Certs) splitCert(fullChain []byte) ([]byte, []byte) {
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

func (c *Certs) info(cert []byte) (string, *x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return "", nil, errors.New("error decoding cert")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, err
	}

	info, err := certinfo.CertificateText(crt)
	return info, crt, err
}

func (c *Certs) writeCert(path string, data string) ([]byte, error) {
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
