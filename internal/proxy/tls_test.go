package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GalaxyGorilla/iec104-shield/internal/config"
	"github.com/GalaxyGorilla/iec104-shield/internal/iec104"
)

type testPKI struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "iec104-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testPKI{
		cert: cert,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (p *testPKI) issue(t *testing.T, cn string, server bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	usage := x509.ExtKeyUsageClientAuth
	if server {
		usage = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func writeTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func dialTLSMaster(t *testing.T, addr string, cfg *tls.Config) *testPeer {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := newTestPeer(conn)
	if err := p.sendU(iec104.UStartDTActive); err != nil {
		t.Fatal(err)
	}
	if err := p.readU(iec104.UStartDTConfirm); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTLSGateway(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	certPEM, keyPEM := pki.issue(t, "127.0.0.1", true)
	certFile := writeTestFile(t, dir, "server.crt", certPEM)
	keyFile := writeTestFile(t, dir, "server.key", keyPEM)

	fake := startFake(t, replyInterrogation)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.TLS = &config.TLSConfig{Cert: certFile, Key: keyFile}
	startReloadRunner(t, dev)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pki.pem)
	m := dialTLSMaster(t, dev.ListenAddr, &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	defer m.close()
	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatalf("TLS interrogation: %v", err)
	}

	// A plain IEC-104 client must be refused before any upstream dial.
	plain, err := net.DialTimeout("tcp", dev.ListenAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	p := newTestPeer(plain)
	_ = p.sendU(iec104.UStartDTActive)
	_ = plain.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := plain.Read(b[:]); err == nil {
		t.Fatal("plain client was not refused by the TLS listener")
	}
}

func TestTLSGatewayRequiresClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	certPEM, keyPEM := pki.issue(t, "127.0.0.1", true)
	certFile := writeTestFile(t, dir, "server.crt", certPEM)
	keyFile := writeTestFile(t, dir, "server.key", keyPEM)
	caFile := writeTestFile(t, dir, "ca.crt", pki.pem)

	fake := startFake(t, replyInterrogation)
	defer fake.close()
	dev := testDevice(fake.addr())
	dev.ListenAddr = freeTCPAddr(t)
	dev.TLS = &config.TLSConfig{Cert: certFile, Key: keyFile, ClientCA: caFile}
	startReloadRunner(t, dev)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pki.pem)
	serverCfg := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}

	// Without a client certificate the handshake must fail.
	bad, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", dev.ListenAddr, serverCfg)
	if err == nil {
		_ = bad.SetDeadline(time.Now().Add(time.Second))
		_ = bad.Handshake()
		var b [1]byte
		_, readErr := bad.Read(b[:])
		_ = bad.Close()
		if readErr == nil {
			t.Fatal("mTLS listener accepted a client without a certificate")
		}
	}

	clientCertPEM, clientKeyPEM := pki.issue(t, "operator", false)
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg.Certificates = []tls.Certificate{clientCert}
	m := dialTLSMaster(t, dev.ListenAddr, serverCfg)
	defer m.close()
	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatalf("mTLS interrogation: %v", err)
	}
}

func startTLSTestOutstation(t *testing.T, pki *testPKI, requireClient bool) *fakeOutstation {
	t.Helper()
	certPEM, keyPEM := pki.issue(t, "127.0.0.1", true)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if requireClient {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pki.pem)
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return startFakeOn(t, tls.NewListener(ln, cfg), replyInterrogation, nil)
}

func TestUpstreamTLS(t *testing.T) {
	pki := newTestPKI(t)
	fake := startTLSTestOutstation(t, pki, false)
	defer fake.close()
	dir := t.TempDir()
	caFile := writeTestFile(t, dir, "ca.crt", pki.pem)

	dev := testDevice(fake.addr())
	dev.DeviceTLS = &config.DeviceTLSConfig{CACert: caFile, ServerName: "127.0.0.1"}
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatalf("interrogation over upstream TLS: %v", err)
	}
}

func TestUpstreamTLSBadCA(t *testing.T) {
	pki := newTestPKI(t)
	fake := startTLSTestOutstation(t, pki, false)
	defer fake.close()
	other := newTestPKI(t)
	dir := t.TempDir()
	caFile := writeTestFile(t, dir, "other-ca.crt", other.pem)

	dev := testDevice(fake.addr())
	dev.DeviceTLS = &config.DeviceTLSConfig{CACert: caFile, ServerName: "127.0.0.1"}
	addr, stop := startGateway(t, dev)
	defer stop()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("master stayed open after the upstream TLS certificate failed")
	}
}

func TestUpstreamTLSClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	fake := startTLSTestOutstation(t, pki, true)
	defer fake.close()
	dir := t.TempDir()
	caFile := writeTestFile(t, dir, "ca.crt", pki.pem)
	clientCertPEM, clientKeyPEM := pki.issue(t, "proxy", false)
	certFile := writeTestFile(t, dir, "client.crt", clientCertPEM)
	keyFile := writeTestFile(t, dir, "client.key", clientKeyPEM)

	dev := testDevice(fake.addr())
	dev.DeviceTLS = &config.DeviceTLSConfig{
		CACert:     caFile,
		ServerName: "127.0.0.1",
		Cert:       certFile,
		Key:        keyFile,
	}
	addr, stop := startGateway(t, dev)
	defer stop()

	m := dialMaster(t, addr)
	defer m.close()
	if err := m.sendI(interrogation(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.readI(); err != nil {
		t.Fatalf("interrogation over upstream mTLS: %v", err)
	}
}
