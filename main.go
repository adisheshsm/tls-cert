// Copyright 2016 Manlio Perillo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// tls-cert is a command used to generate self signed certificate for servers
// and client.  The command requires two positional arguments with the
// Organization and Common Name.
//
// By default a server certificate is generated, and Common Name should be set
// to the server primary DNS name.  Additional DNS names and IP addresses are
// not supported.
//
// When the -client flag is specified, a client certificate is generated, and
// Common Name should be set to an email address.
//
// The command is designed to make it easy to setup mutual authentication using
// TLS.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

// A Config structure is used to generate a TLS certificate.
type Config struct {
	Organization string
	CommonName   string
	KeyUsage     x509.ExtKeyUsage
	Lifetime     time.Duration
}

const help = `
tls-cert is a command used to generate self signed certificate for server and
client.  The command requires two positional arguments with the Organization
and Common Name.

By default a server certificate is generated, and Common Name should be set to
the server primary DNS name.  Additional DNS names and IP addresses are not
supported.

When the -client flag is specified, a client certificate is generated, and
Common Name should be set to an email address.

The command is designed to make it easy to setup mutual authentication using
TLS.
`

var (
	client   = flag.Bool("client", false, "generate certificate for client")
	lifetime = flag.Int("lifetime", 365, "certificate lifetime in days")
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

	var keyName string
	var certName string

	O := flag.Arg(0)
	CN := flag.Arg(1)
	config := Config{
		Organization: O,
		CommonName:   CN,
		Lifetime:     time.Duration(*lifetime) * 24 * time.Hour,
	}
	if *client {
		config.KeyUsage = x509.ExtKeyUsageClientAuth
		keyName = fmt.Sprintf("%s-%s.key", O, "client")
		certName = fmt.Sprintf("%s-%s.crt", O, "client")
	} else {
		config.KeyUsage = x509.ExtKeyUsageServerAuth
		keyName = fmt.Sprintf("%s-%s.key", O, "server")
		certName = fmt.Sprintf("%s-%s.crt", O, "server")
	}

	// Generate private key and self signed certificate.
	key, err := GenerateKey()
	if err != nil {
		log.Fatal(err)
	}
	cert, err := CreateCert(key, config)
	if err != nil {
		log.Fatal(err)
	}

	if err := WriteKey(key, keyName); err != nil {
		log.Fatal(err)
	}
	if err := WriteCert(cert, certName); err != nil {
		log.Fatal(err)
	}
}

// GenerateKey generates a private key.
// Key size is fixed at 2048, since this is the common size for TLS as used
// today.
func GenerateKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %v", err)
	}

	return key, nil
}

// CreateCert creates a self signed certificate using specified private key.
func CreateCert(key *rsa.PrivateKey, config Config) ([]byte, error) {
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

		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{config.KeyUsage},
		BasicConstraintsValid: true,

		IsCA: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template,
		&key.PublicKey, key)
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
