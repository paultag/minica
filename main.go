package main

import (
	"flag"
	"fmt"
	"os"
)

func Missing(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
	}
	return false
}

func main() {
	caCrt := "cacert.crt"
	caKey := "cacert.key"
	/* If doesn't exist, create the CA  */

	org := "Paul Tagliamonte"

	commonName := flag.String("common-name", "", "CN of the cert")
	certType := flag.String("type", "client", "client or server")
	flag.Parse()

	isClientCert := false
	switch *certType {
	case "client":
		isClientCert = true
	case "server":
		isClientCert = false
	default:
		panic(fmt.Errorf("Unknown type"))
	}

	if Missing(caCrt, caKey) {
		if err := GenerateCACertificate(
			caCrt, caKey,
			"Example Inc", "example.com",
			2048,
		); err != nil {
			panic(err)
		}
	}

	cn := *commonName

	newCrt := fmt.Sprintf("%s.crt", cn)
	newKey := fmt.Sprintf("%s.key", cn)

	if err := GenerateCert(
		[]string{cn},
		newCrt, newKey, caCrt, caKey,
		org, cn,
		2048,
		isClientCert,
	); err != nil {
		panic(err)
	}
}
