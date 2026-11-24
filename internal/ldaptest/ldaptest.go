// Package ldaptest starts an OpenLDAP server (slapd) for tests: in a temporary folder, on
// free ports of 127.0.0.1, with ldap:// (StartTLS possible) and ldaps://, a certificate of
// its own and the entries of Seed. Tests are skipped where slapd is not installed (e.g. on
// Windows); on Debian or Ubuntu: apt-get install slapd.
package ldaptest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Base is the suffix of the directory; Admin and AdminPassword the administrator.
const (
	Base          = "dc=example,dc=org"
	Admin         = "cn=admin,dc=example,dc=org"
	AdminPassword = "admin-pw"
)

// Photo is the jpegPhoto of alice: bytes that are not UTF-8.
var Photo = []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10}

// Seed are the entries of the directory.
const Seed = `dn: dc=example,dc=org
objectClass: dcObject
objectClass: organization
dc: example
o: Example

dn: ou=people,dc=example,dc=org
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: alice
cn: Alice Doe
sn: Doe
mail: alice@example.org
userPassword: alice-pw
jpegPhoto:: /9j/4AAQ

dn: uid=bob,ou=people,dc=example,dc=org
objectClass: inetOrgPerson
uid: bob
cn: Bob Roe
sn: Roe
mail: bob@example.org
mail: robert@example.org
userPassword: bob-pw

dn: cn=staff,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: staff
member: uid=alice,ou=people,dc=example,dc=org
member: uid=bob,ou=people,dc=example,dc=org
`

// Server is a running slapd.
type Server struct {
	URL    string // ldap://127.0.0.1:<port>
	TLSURL string // ldaps://127.0.0.1:<port>
	CAFile string // PEM file with the certificate of the server
}

var slapdPaths = []string{"/usr/sbin/slapd", "/usr/local/sbin/slapd", "/usr/local/libexec/slapd"}

// Start starts slapd and stops it at the end of the test.
func Start(t testing.TB) *Server {
	t.Helper()
	slapd := os.Getenv("SLAPD")
	if slapd == "" {
		for _, p := range slapdPaths {
			if _, err := os.Stat(p); err == nil {
				slapd = p
				break
			}
		}
	}
	if slapd == "" {
		t.Skip("slapd is not installed (apt-get install slapd); set SLAPD to its path")
	}
	dir := t.TempDir()
	caFile, certFile, keyFile := writeCertificates(t, dir)
	dbDir := filepath.Join(dir, "db")
	if err := os.Mkdir(dbDir, 0o700); err != nil {
		t.Fatal(err)
	}
	modules := ""
	for _, p := range []string{"/usr/lib/ldap", "/usr/lib64/openldap", "/usr/local/libexec/openldap"} {
		if _, err := os.Stat(filepath.Join(p, "back_mdb.so")); err == nil {
			modules = fmt.Sprintf("modulepath %s\nmoduleload back_mdb\n", p)
		}
	}
	schema := "/etc/ldap/schema"
	if _, err := os.Stat(schema); err != nil {
		schema = "/etc/openldap/schema"
	}
	conf := filepath.Join(dir, "slapd.conf")
	write(t, conf, fmt.Sprintf(`include %[1]s/core.schema
include %[1]s/cosine.schema
include %[1]s/inetorgperson.schema
%[2]s
pidfile %[3]s/slapd.pid
TLSCACertificateFile %[4]s
TLSCertificateFile %[5]s
TLSCertificateKeyFile %[6]s

database mdb
maxsize 10485760
suffix "%[7]s"
rootdn "%[8]s"
rootpw %[9]s
directory %[10]s
access to attrs=userPassword
  by self write
  by anonymous auth
  by * none
access to *
  by * read
`, schema, modules, dir, caFile, certFile, keyFile, Base, Admin, AdminPassword, dbDir))
	ldif := filepath.Join(dir, "seed.ldif")
	write(t, ldif, Seed)
	ctx := context.Background()
	if out, err := exec.CommandContext(ctx, filepath.Join(filepath.Dir(slapd), "slapadd"), "-f", conf, "-l", ldif).CombinedOutput(); err != nil {
		// slapadd is often a link to slapd, which acts by its name.
		if out2, err2 := exec.CommandContext(ctx, slapd, "-T", "add", "-f", conf, "-l", ldif).CombinedOutput(); err2 != nil {
			t.Fatalf("slapadd: %v\n%s\n%s", err, out, out2)
		}
	}
	port, tlsPort := freePort(t), freePort(t)
	s := &Server{URL: fmt.Sprintf("ldap://127.0.0.1:%d", port), TLSURL: fmt.Sprintf("ldaps://127.0.0.1:%d", tlsPort), CAFile: caFile}
	var log bytes.Buffer
	cmd := exec.CommandContext(ctx, slapd, "-f", conf, "-h", s.URL+"/ "+s.TLSURL+"/", "-d", "0")
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatalf("slapd: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	for _, p := range []int{port, tlsPort} {
		deadline := time.Now().Add(10 * time.Second)
		for {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("slapd does not listen on %d: %v\n%s", p, err, log.String())
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return s
}

func write(t testing.TB, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t testing.TB) int {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// writeCertificates writes a CA and a certificate for 127.0.0.1 and localhost signed by it.
func writeCertificates(t testing.TB, dir string) (caFile, certFile, keyFile string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ldaptest CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile, certFile, keyFile = filepath.Join(dir, "ca.pem"), filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	write(t, caFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
	write(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	write(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	return caFile, certFile, keyFile
}
