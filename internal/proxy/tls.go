package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
)

// tlsConfigFor builds the master-facing TLS termination config. The
// outstation leg stays plaintext: the master is the untrusted side and the
// legacy RTU is what the appliance protects. TLS 1.2 is the minimum; mTLS is
// required when a client CA is configured.
func tlsConfigFor(dev config.Device) (*tls.Config, error) {
	if dev.TLS == nil {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(dev.TLS.Cert, dev.TLS.Key)
	if err != nil {
		return nil, fmt.Errorf("tls: load server cert/key: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if dev.TLS.ClientCA != "" {
		pem, err := os.ReadFile(dev.TLS.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("tls: read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls: client CA %s: no valid certificates found", dev.TLS.ClientCA)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
