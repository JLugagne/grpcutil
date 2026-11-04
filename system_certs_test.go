package grpcutil_test

import (
	"context"
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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/authzed/grpcutil"
)

const (
	subprocessEnv    = "GRPCUTIL_SYSTEM_CERTS_SUBPROCESS"
	serverAddrEnv    = "GRPCUTIL_SYSTEM_CERTS_SERVER_ADDR"
	fallbackCAEnv    = "GRPCUTIL_SYSTEM_CERTS_FALLBACK_CA"
	healthRPCTimeout = 5 * time.Second
)

func TestWithSystemCertsTrustsSystemRoots(t *testing.T) {
	if isSubprocess() {
		require.NoError(t, checkHealth(t, systemCerts(t, true)))
		return
	}

	requireLinux(t)
	ca := newTestCA(t)
	runSubprocess(t,
		"SSL_CERT_FILE="+ca.writePEM(t),
		"SSL_CERT_DIR="+t.TempDir(),
		serverAddrEnv+"="+startTLSServer(t, ca),
	)
}

func TestWithSystemCertsRejectsUnknownCA(t *testing.T) {
	if isSubprocess() {
		err := checkHealth(t, systemCerts(t, true))
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.ErrorContains(t, err, "certificate signed by unknown authority")
		return
	}

	requireLinux(t)
	runSubprocess(t,
		"SSL_CERT_FILE="+newTestCA(t).writePEM(t),
		"SSL_CERT_DIR="+t.TempDir(),
		serverAddrEnv+"="+startTLSServer(t, newTestCA(t)),
	)
}

func TestWithSystemCertsSkipVerifyCAAcceptsUnknownCA(t *testing.T) {
	if isSubprocess() {
		require.NoError(t, checkHealth(t, systemCerts(t, false)))
		return
	}

	requireLinux(t)
	runSubprocess(t,
		"SSL_CERT_FILE="+newTestCA(t).writePEM(t),
		"SSL_CERT_DIR="+t.TempDir(),
		serverAddrEnv+"="+startTLSServer(t, newTestCA(t)),
	)
}

// TestSystemCertPoolSucceedsWithoutSystemRoots pins the stdlib behavior that
// makes an embedded CA fallback in WithSystemCerts unreachable on Linux: a
// host without any root bundle yields an empty pool, not an error.
func TestSystemCertPoolSucceedsWithoutSystemRoots(t *testing.T) {
	if isSubprocess() {
		pool, err := x509.SystemCertPool()
		require.NoError(t, err)
		require.NotNil(t, pool)

		_, err = grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		require.NoError(t, err)

		err = checkHealth(t, systemCerts(t, true))
		require.ErrorContains(t, err, "certificate signed by unknown authority")
		return
	}

	requireLinux(t)
	missing := t.TempDir()
	runSubprocess(t,
		"SSL_CERT_FILE="+filepath.Join(missing, "missing.pem"),
		"SSL_CERT_DIR="+filepath.Join(missing, "missing"),
		serverAddrEnv+"="+startTLSServer(t, newTestCA(t)),
	)
}

// TestWithSystemCertsUsesFallbackRootsWithoutSystemRoots proves that binaries
// built without system roots can rely on x509.SetFallbackRoots, which is what
// golang.org/x/crypto/x509roots/fallback calls on import.
func TestWithSystemCertsUsesFallbackRootsWithoutSystemRoots(t *testing.T) {
	if isSubprocess() {
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM([]byte(os.Getenv(fallbackCAEnv))))
		x509.SetFallbackRoots(roots)

		require.NoError(t, checkHealth(t, systemCerts(t, true)))
		return
	}

	requireLinux(t)
	ca := newTestCA(t)
	missing := t.TempDir()
	runSubprocess(t,
		"SSL_CERT_FILE="+filepath.Join(missing, "missing.pem"),
		"SSL_CERT_DIR="+filepath.Join(missing, "missing"),
		fallbackCAEnv+"="+string(ca.pem()),
		serverAddrEnv+"="+startTLSServer(t, ca),
	)
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "grpcutil test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testCA{cert: cert, key: key}
}

func (ca testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

func (ca testCA) writePEM(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, ca.pem(), 0o600))
	return path
}

func (ca testCA) issueServerCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func startTLSServer(t *testing.T, ca testCA) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	cert := ca.issueServerCert(t)
	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	return lis.Addr().String()
}

func systemCerts(t *testing.T, verifyCA bool) grpc.DialOption {
	t.Helper()

	v := grpcutil.SkipVerifyCA
	if verifyCA {
		v = grpcutil.VerifyCA
	}
	opt, err := grpcutil.WithSystemCerts(v)
	require.NoError(t, err)
	return opt
}

func checkHealth(t *testing.T, opt grpc.DialOption) error {
	t.Helper()

	conn, err := grpc.NewClient(os.Getenv(serverAddrEnv), opt)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), healthRPCTimeout)
	defer cancel()

	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func isSubprocess() bool {
	return os.Getenv(subprocessEnv) != ""
}

func requireLinux(t *testing.T) {
	t.Helper()

	if runtime.GOOS != "linux" {
		t.Skip("SSL_CERT_FILE and SSL_CERT_DIR only drive the system pool on Linux")
	}
}

func runSubprocess(t *testing.T, env ...string) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v") //nolint:gosec // re-executes the current test binary
	cmd.Env = append(os.Environ(), subprocessEnv+"=1")
	cmd.Env = append(cmd.Env, env...)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	require.True(t, strings.Contains(string(out), "--- PASS: "+t.Name()), "subprocess did not run %s:\n%s", t.Name(), out)
}
