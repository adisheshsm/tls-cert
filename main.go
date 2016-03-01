// Copyright 2016 Manlio Perillo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// tls-cert is a command used to simplify the generation of certificate for
// server and client.  The command requires two positional arguments with the
// Organization and Common Name.
//
// When a server certificate is generated, Common Name should be set to the
// server primary DNS name and Organization should be set to the name of the
// software.  Additional DNS names and IP addresses are not supported.
//
// When a client certificate is generated, Common Name should be set to the
// user email address and Organization to the name of the software.
//
// When a CA certificate is generated, Common Name should be set to the user
// name and Organization to the user full name.
//
// The generated certificate can be verified using
//	openssl x509 -noout -text -in name.crt
//
// A PKCS12 file for use in a browser (for client authentication) can be
// generated with
//      openssl pkcs12 -inkey name.key -in name.crt -export -out name.p12
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

type Certificate struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// A Config structure is used to generate a TLS certificate.
type Config struct {
	Organization string
	CommonName   string
	KeySize      int
	KeyUsage     x509.KeyUsage
	ExtKeyUsage  x509.ExtKeyUsage
	Lifetime     time.Duration
}

const help = `
When a server certificate is generated, Common Name should be set to the
server primary DNS name and Organization should be set to the name of the
software.

When a client certificate is generated, Common Name should be set to the user
email address and Organization to the name of the software.

When a CA certificate is generated, Common Name should be set to the user name
and Organization to the user full name.
`

var (
	usage    = flag.String("usage", "server", "usage of the certificate")
	lifetime = flag.Int("lifetime", 0, "certificate lifetime in days")
	caName   = flag.String("ca", "", "name of the CA to use for signing")
)

var (
	// The default RSA key size.
	// CA certificates have a long lifetime so 4096 is used, while server and
	// client certificates have a short lifetime and TLS should be as fast as
	// possible, so 2048 is used.
	defaultKeySize = map[string]int{
		"ca":     4096,
		"server": 2048,
		"client": 2048,
	}

	// The default certificate lifetime, in days.
	defaultLifetime = map[string]int{
		"ca":     10 * 365,
		"server": 365,
		"client": 365,
	}
)

func main() {
	// Setup log.
	log.SetFlags(0)

	// Parse command line.
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tls-cert [flags] Organization CommonName")
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, help)
		os.Exit(2)
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}
	if *usage != "ca" && *usage != "server" && *usage != "client" {
		flag.Usage()
		os.Exit(2)
	}

	var keyName string
	var certName string

	O := flag.Arg(0)
	CN := flag.Arg(1)
	if *lifetime == 0 {
		*lifetime = defaultLifetime[*usage]
	}
	config := Config{
		Organization: O,
		CommonName:   CN,
		KeySize:      defaultKeySize[*usage],
		Lifetime:     time.Duration(*lifetime) * 24 * time.Hour,
	}

	switch *usage {
	case "ca":
		config.KeyUsage = x509.KeyUsageCertSign
		config.ExtKeyUsage = x509.ExtKeyUsageAny
		keyName = fmt.Sprintf("%s-%s.key", CN, "ca")
		certName = fmt.Sprintf("%s-%s.crt", CN, "ca")
	case "server":
		config.KeyUsage = x509.KeyUsageKeyEncipherment
		config.ExtKeyUsage = x509.ExtKeyUsageServerAuth
		keyName = fmt.Sprintf("%s-%s.key", O, "server")
		certName = fmt.Sprintf("%s-%s.crt", O, "server")
	case "client":
		config.KeyUsage = x509.KeyUsageKeyEncipherment
		config.ExtKeyUsage = x509.ExtKeyUsageClientAuth
		keyName = fmt.Sprintf("%s-%s.key", O, "client")
		certName = fmt.Sprintf("%s-%s.crt", O, "client")
	}

	key, err := GenerateKey(config)
	if err != nil {
		log.Fatal(err)
	}
	if err := WriteKey(key, keyName); err != nil {
		log.Fatal(err)
	}

	var cert []byte

	if *caName == "" {
		cert, err = CreateSelfSignedCert(key, config)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		ca, err := LoadCA(*caName)
		if err != nil {
			log.Fatal(err)
		}
		cert, err = CreateCert(key, ca, config)
		if err != nil {
			log.Fatal(err)
		}
	}
	if err := WriteCert(cert, certName); err != nil {
		log.Fatal(err)
	}
}

// GenerateKey generates a private key.
func GenerateKey(config Config) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %v", err)
	}

	return key, nil
}

// CreateSelfSignedCert creates a self signed certificate using specified
// private key.
func CreateSelfSignedCert(key *rsa.PrivateKey, config Config) ([]byte, error) {
	now := time.Now()

	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},

		NotBefore: now,
		NotAfter:  now.Add(config.Lifetime),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | config.KeyUsage,
		BasicConstraintsValid: true,

		IsCA: true,
	}
	if config.ExtKeyUsage != x509.ExtKeyUsageAny {
		template.ExtKeyUsage = []x509.ExtKeyUsage{config.ExtKeyUsage}
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %v", err)
	}

	return cert, nil
}

// CreateCert creates a certificate using the specified private key (only the
// public part will be used) and signed using specified CA.
func CreateCert(key *rsa.PrivateKey, ca *Certificate, config Config) ([]byte, error) {
	now := time.Now()

	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			Organization: []string{config.Organization},
			CommonName:   config.CommonName,
		},

		NotBefore: now,
		NotAfter:  now.Add(config.Lifetime),

		KeyUsage:    x509.KeyUsageDigitalSignature | config.KeyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{config.ExtKeyUsage},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate,
		&key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %v", err)
	}

	return cert, nil
}

// WriteKey writes the private key to path.  The file will be accessible only
// to current user.
func WriteKey(key *rsa.PrivateKey, path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	b := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := pem.Encode(file, &b); err != nil {
		// Encode can fail only for I/O errors.
		return fmt.Errorf("writing private key to %q: %v", path, err)
	}

	return nil
}

// WriteCert writes the certificate to path.
func WriteCert(cert []byte, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	b := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	}
	if err := pem.Encode(file, &b); err != nil {
		return fmt.Errorf("writing certificate to %q: %v", path, err)
	}

	return nil
}

// LoadCA loads CA certificate and private key pair.
func LoadCA(name string) (*Certificate, error) {
	// NOTE(mperillo): We do not use the tls.LoadX509KeyPair function, since
	// the certificate is stored as raw bytes, and not as x509.Certificate.
	// It also supports chained certificates, and we don't need them.
	certName := fmt.Sprintf("%s-%s.crt", name, "ca")
	keyName := fmt.Sprintf("%s-%s.key", name, "ca")

	// Load certificate.
	data, err := loadPem(certName)
	if err != nil {
		return nil, fmt.Errorf("reading CA certificate file: %v", err)
	}
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %v", err)
	}

	// Load private key.
	data, err = loadPem(keyName)
	if err != nil {
		return nil, fmt.Errorf("reading CA key file: %v", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %v", err)
	}

	ca := Certificate{
		Certificate: cert,
		PrivateKey:  key,
	}

	return &ca, nil
}

func loadPem(path string) ([]byte, error) {
	buf, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Ignore errors and additional blocks.
	// Any problem will be report by either ParsePKCS1PrivateKey or
	// ParseCertificate functions.
	data, _ := pem.Decode(buf)
	if data == nil {
		return []byte(""), nil
	}

	return data.Bytes, nil
}
