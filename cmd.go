package main

import (
	"flag"
	"fmt"
)

/* Определение поддерживаемых параметров командной строки */
var (
	// Флаги командной строки, не используемые в конфиге
	clpConfigPath = flag.String("config", "", "`path to config file` in JSONC format")
	clpShowHelp   = flag.Bool("help", false, "Show help and exit (this message)")

	// Короткая справка по параметрам командной строки
	clpUsageFunc = func() {
		fmt.Printf(`ncatos utility allows to periodically query NCA OCSP/TSP servers
gathering succeed/failed request count.

Failed request are partitioned on types:
  - "net" - network related errors (HTTP timeout, disconnects, etc...);
  - "format" - received requests failed to parse (not ASN.1/wrong ASN.1);
  - "contents" - request succeeds to parse, but contains unexpected contents (wrong status, not expected nonce, etc...).

Command line flags:
`)
		flag.CommandLine.PrintDefaults()
	}

	// конфигурация протоколирования
	clpLogEnabled  = flag.Bool("log.enabled", false, "flag allows to enable utility logging")
	clpLogConsole  = flag.Bool("log.console", false, "flag enables console logging if set to true")
	clpLogFileName = flag.String("log.filename", "", "enables logging to file with given `filename` if set. Use with caution - file size, rotate, etc...")
	clpLogVerbose  = flag.Bool("log.verbose", false, "flag allows to dump base64 encoded requests/responses to log")

	// конфигурация сбора метрик
	clpMetricsEnabled = flag.Bool("metrics.enabled", false, "flag allows to enable metrics monitoring via HTTP (Prometheus)")
	clpMetricsAddress = flag.String("metrics.address", "", "serve metrics on given [host:port]")

	// конфигурация OCSP
	clpOcspDisabled        = flag.Bool("ocsp.disabled", false, "flag allows to disable quering OCSP server (true)")
	clpOcspURL             = flag.String("ocsp.url", "", "OCSP server URL")
	clpOcspTimeout         = flag.String("ocsp.timeout", "", "network timeout for OCSP server (empty string - no timeout)")
	clpOcspDigestOID       = flag.String("ocsp.digestoid", "", "digest OID used to create OCSP CertID")
	clpOcspNameDigest      = flag.String("ocsp.namedigest", "", "base64 encoded digest value of queried certificate issuer name")
	clpOcspKeyDigest       = flag.String("ocsp.keydigest", "", "base64 encoded digest value of queried certificate issuer public key")
	clpOcspCert            = flag.String("ocsp.cert", "", "base64 encoded certificate to query OCSP status (here - ASN.1 DER in BASE64)")
	clpOcspCertFile        = flag.String("ocsp.certfile", "", "`path to certificate file` whose status is required to ask. Certificate file is loaded only if `cert` is empty (including config)")
	clpOcspNonceSize       = flag.Int("ocsp.noncesize", defaultOcspNonceSize, "OCSP nonce (randomly generated data) size (in bytes, 0 - do not use)")
	clpOcspRetryCount      = flag.Int("ocsp.retrycount", 0, "number of times to send OCSP request with retryinterval timeout between them (0 - endless)")
	clpOcspRetryInterval   = flag.String("ocsp.retryinterval", defaultOcspRetryInterval, "timeout between sending two OCSP requests attempts (empty string - no timeout)")
	clpOcspMaxResponseSize = flag.Int64("ocsp.maxresponsesize", defaultOcspMaxResponseSize, "maximum size of OCSP server response (bytes)")

	// конфигурация TSP
	clpTspDisabled        = flag.Bool("tsp.disabled", false, "flag allows to disable quering TSP server (true)")
	clpTspURL             = flag.String("tsp.url", "", "TSP server URL")
	clpTspTimeout         = flag.String("tsp.timeout", "", "network timeout for TSP server (empty string - no timeout)")
	clpTspDigestOID       = flag.String("tsp.digestoid", "", "digest OID used to digest TSP timestamp-ed data (here MessageImprint.HashAlgorithm)")
	clpTspPolicyOID       = flag.String("tsp.policyoid", "", "policy OID under which TSP timestamp must be created")
	clpTspDigest          = flag.String("tsp.digest", "", "base64 encoded TSP timestamp-ed digest value. This or `tsp.digestsize` parameters must be given (here value of MessageImprint.HashedMessage)")
	clpTspDigestSize      = flag.Int("tsp.digestsize", 0, "digest size of algorithm used to digest TSP timestamp-ed data. If `tsp.digest` is empty then random data of given size is generated and used to create TSP MessageImprint")
	clpTspNonceSize       = flag.Int("tsp.noncesize", defaultTspNonceSize, "TSP nonce (randomly generated data) size (in bytes, 0 - do not use)")
	clpTspRetryCount      = flag.Int("tsp.retrycount", 0, "number of times to send TSP request with retryinterval timeout between them (0 - endless)")
	clpTspRetryInterval   = flag.String("tsp.retryinterval", defaultTspRetryInterval, "timeout between sending two TSP requests attempts (empty string - no timeout)")
	clpTspMaxResponseSize = flag.Int64("tsp.maxresponsesize", defaultTspMaxResponseSize, "maximum size of TSP server response (bytes)")
)
