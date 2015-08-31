package main

import (
	"flag"
)

func main() {
	// caCrt := "cacert.crt"
	// caKey := "cacert.key"
	/* If doesn't exist, create the CA  */

	flag.String("common-name", "", "CN of the cert")
	flag.Parse()
}
