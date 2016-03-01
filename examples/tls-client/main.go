// Copyright 2016 Manlio Perillo. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build example

// tls-client tests mutual authentication with TLS.
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

var ca = flag.String("ca", "", "name of the CA")

func main() {
	// Setup log.
	log.SetFlags(0)

	// Parse command line.
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: tls-client [flags] Organization")
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

	cert, err := LoadClientCert(O)
	if err != nil {
		log.Fatal(err)
	}

	var caCert *x509.CertPool

	if *ca == "" {
		caCert, err = LoadServerCert(O)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		caCert, err = LoadCACert(*ca)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Setup HTTPS client.
	config := tls.Config{
		Certificates: []tls.Certificate{*cert},
		RootCAs:      caCert,
	}
	//config.BuildNameToCertificate()

	client := NewClient(&config)
	resp, err := client.Get("https://localhost:8080/hello")
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	if err != nil {
		log.Fatal(err)
	}
}

func NewClient(config *tls.Config) *http.Client {
	transport := http.Transport{TLSClientConfig: config}

	return &http.Client{Transport: &transport}
}

func LoadClientCert(organization string) (*tls.Certificate, error) {
	keyName := fmt.Sprintf("%s-%s.key", organization, "client")
	certName := fmt.Sprintf("%s-%s.crt", organization, "client")

	cert, err := tls.LoadX509KeyPair(certName, keyName)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %v", err)
	}

	return &cert, nil
}

func LoadServerCert(organization string) (*x509.CertPool, error) {
	certName := fmt.Sprintf("%s-%s.crt", organization, "server")

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
