/* {{{ Copyright 2015 Paul R. Tagliamonte <paultag@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. }}} */

package main

import (
	"fmt"
	"os"

	"pault.ag/go/config"
)

func Missing(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return true
		}
	}
	return false
}

type MiniCA struct {
	KeySize      int    `flag:"key-size"       description:"Key Size"`
	CommonName   string `flag:"common-name"    description:"Common Name of the Cert"`
	Org          string `flag:"conf.Org"       description:"Organization of the Cert"`
	Type         string `flag:"type"           description:"Cert Type (client or server)"`
	CaCommonName string `flag:"ca-common-name" description:"Common Name of the CA Cert"`
	CaCert       string `flag:"ca-cert"        description:"Path to the CA Cert"`
	CaKey        string `flag:"ca-key"         description:"Path to the CA Key"`
	CaKeySize    int    `flag:"ca-key-size"    description:"CA Key Size"`
}

func main() {
	conf := MiniCA{
		Org:       "Example Organization",
		KeySize:   2048,
		CaCert:    "cacert.crt",
		CaKey:     "cakey.key",
		CaKeySize: 2048,
	}
	flags, err := config.LoadFlags("minica", &conf)
	if err != nil {
		panic(err)
	}

	flags.Parse(os.Args[1:])

	if conf.CommonName == "" {
		flags.Usage()
		return
	}

	if Missing(conf.CaCert, conf.CaKey) {
		if err := GenerateCACertificate(
			conf.CaCert, conf.CaKey,
			conf.Org, conf.CaCommonName,
			conf.CaKeySize,
		); err != nil {
			panic(err)
		}
	}

	isClientCert := false
	switch conf.Type {
	case "client":
		isClientCert = true
	case "server":
		isClientCert = false
	default:
		fmt.Printf(`Unknown cert type!

Currently supported types:

	client
	server

`)
		flags.Usage()
		os.Exit(2)
	}

	cn := conf.CommonName
	newCrt := fmt.Sprintf("%s.crt", cn)
	newKey := fmt.Sprintf("%s.key", cn)

	fmt.Printf(`Creating a %s cert:

Common Name: %s
Org:         %s
Cert Flavor: %s
Output crt:  %s
Output key:  %s
`, conf.Type, conf.CommonName, conf.Org, conf.Type, newCrt, newKey)

	if err := GenerateCert(
		[]string{cn},
		newCrt, newKey, conf.CaCert, conf.CaKey,
		conf.Org, cn,
		conf.KeySize,
		isClientCert,
	); err != nil {
		panic(err)
	}
}

// vim: foldmethod=marker
