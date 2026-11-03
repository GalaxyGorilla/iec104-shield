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

// deviceTLSConfigFor builds the upstream (outstation-side) TLS client config.
// The proxy is the TLS client here; a bad certificate fails the upstream dial,
// which closes the master session (fail closed).
func deviceTLSConfigFor(dev config.Device) (*tls.Config, error) {
	if dev.DeviceTLS == nil {
		return nil, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if dev.DeviceTLS.CACert != "" {
		pem, err := os.ReadFile(dev.DeviceTLS.CACert)
		if err != nil {
			return nil, fmt.Errorf("device_tls: read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("device_tls: CA cert %s: no valid certificates found", dev.DeviceTLS.CACert)
		}
		cfg.RootCAs = pool
	}
	if dev.DeviceTLS.ServerName != "" {
		cfg.ServerName = dev.DeviceTLS.ServerName
	}
	if dev.DeviceTLS.Cert != "" && dev.DeviceTLS.Key != "" {
		cert, err := tls.LoadX509KeyPair(dev.DeviceTLS.Cert, dev.DeviceTLS.Key)
		if err != nil {
			return nil, fmt.Errorf("device_tls: load client cert/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
