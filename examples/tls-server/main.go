// Copyright 2016 Manlio Perillo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build example

// tls-server tests mutual authentication with TLS.
//
// When using self signed certificates, verify authentication with:
//	./tls-server O &
//	./tls-client O
// When using a certificate authority, verify authentication with:
//	./tls-server -ca CN O &
//	./tls-client -ca CN O
// where O is the Organization name and CN is the Common Name of the authority.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "hello, world!\n")
}

func init() {
	http.HandleFunc("/hello", HelloServer)
}

var ca = flag.String("ca", "", "name of the CA")

func main() {
	// Setup log.
	log.SetFlags(0)

	// Parse command line.
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tls-server [flags] Organization")
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	O := flag.Arg(0)

	cert, err := LoadServerCert(O)
	if err != nil {
		log.Fatal(err)
	}

	var caCert *x509.CertPool

	if *ca == "" {
		caCert, err = LoadClientCert(O)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		caCert, err = LoadCACert(*ca)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Setup HTTPS server.
	config := tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    caCert,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	//config.BuildNameToCertificate()

	if err := ListenAndServeTLS("localhost:8080", &config); err != nil {
		log.Fatal(err)
	}
}

func ListenAndServeTLS(addr string, config *tls.Config) error {
	server := &http.Server{
		Addr:      ":8080",
		TLSConfig: config,
	}

	// Certificate and matching private key are already provided via config.
	return server.ListenAndServeTLS("", "")
}

func LoadServerCert(organization string) (*tls.Certificate, error) {
	keyName := fmt.Sprintf("%s-%s.key", organization, "server")
	certName := fmt.Sprintf("%s-%s.crt", organization, "server")

	cert, err := tls.LoadX509KeyPair(certName, keyName)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %v", err)
	}

	return &cert, nil
}

func LoadClientCert(organization string) (*x509.CertPool, error) {
	certName := fmt.Sprintf("%s-%s.crt", organization, "client")

	return loadCACert(certName)
}
func LoadCACert(cname string) (*x509.CertPool, error) {
	certName := fmt.Sprintf("%s-%s.crt", cname, "ca")

	return loadCACert(certName)
}

func loadCACert(path string) (*x509.CertPool, error) {
	cert, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)

	return pool, nil
}
