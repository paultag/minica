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

	commonName := flag.String("common-name", "", "CN of the cert")
	org := flag.String("org", "Widgets, Inc", "Org of the cert")
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

	cn := *commonName
	newCrt := fmt.Sprintf("%s.crt", cn)
	newKey := fmt.Sprintf("%s.key", cn)

	fmt.Printf(`Creating a client cert:

Common Name: %s
Org:         %s
Client Cert: %t
Output crt:  %s
Output key:  %s
`, *commonName, *org, isClientCert, newCrt, newKey)

	if Missing(caCrt, caKey) {
		fmt.Printf("CA Cert missing, re-creating\n")
		if err := GenerateCACertificate(
			caCrt, caKey,
			*org, "minica.example.com",
			2048,
		); err != nil {
			panic(err)
		}
	}

	if err := GenerateCert(
		[]string{cn},
		newCrt, newKey, caCrt, caKey,
		*org, cn,
		2048,
		isClientCert,
	); err != nil {
		panic(err)
	}
}
