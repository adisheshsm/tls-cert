# tls-cert command

The `tls-cert` command simplify the creation of TLS certificates when mutual
authentication is required.  The command support both self-signed certificates
and certificates signed by a private CA.

## Usage

`$ tls-cert [flags] Organization CommonName`

### Server certificate

By default `tls-cert` will create a server certificate.  `Organization` should
be the name of the software and `CommonName` the primary DNS of the server.

As an example:

`$ tls-cert test localhost`

will create the `test-server.key` and `test-server.crt` files.

### Client certificate

When the `-usage` flag is set to `client`, `tls-cert` will create a client
certificate.  `Organization` should be the name of the software (the same one
used for the server certificate) and `CommonName` the user email address.

As an example:

`$tls-cert` test manlio.perillo@gmail.com

will create the `test-client.key` and `test-client.crt` files.

### CA certificate

Using self-signed certificates is simple, but does not scale well when several
clients with different certificates need to connect to a server.  Another
problem is that Chromium does not support self-signed certificates.

`tls-cert` will create a CA certificate when the `-usage` flag is set to `ca`.
`Organization` should be the user full name and `CommonName` the user name or
nickname.

As an example:

`$ tls-cert manlio "Manlio Perillo"`

will create the `manlio-ca.key` and `manlio-ca.crt` files.

In order to sign a server or client certificate with a CA, set the `-ca` flag
to the CA `CommonName`.

As an example:

`$ tls-cert -ca manlio test localhost`

`$ tls-cert -ca manlio -client test manlio.perillo@gmail.com`

## Using client certificate in a browser

Browsers support certificates in PKCS12 format.  Currently this format is not
supported by `tls-cert`, so `openssl` must be used.

As an example:

`$ openssl pkcs12 -inkey test-client.key -in test-client.crt -export -out name.p12`

Add the CA `.crt` file in the list of trusted authorities, and add the `.p12`
file to the list of your certificates.  Only tested with Chromium.

## Code examples

A simple HTTPS server and client are available in the `examples/tls-server` and
`examples/tls-client` directories.

The commands require the `Organization` as argument.  By default self-signed
certificates are assumed.  Use of a CA can be specified with the `-ca` flag set
to the `CommonName` of the authority.

As an example:

`$ tls-server test &`

`$ tls-client test`

or:

`$ tls-server -ca manlio test &`

`$ tls-client -ca manlio test`

In order to build the examples, specify the `example` build tag
(e.g. `go build -tags example examples/tls-server`), or run them using the
`go run` command (e.g. `go run examples/tls-server/main`).

The examples must be executed from the same directory where certificate files
are stored.
