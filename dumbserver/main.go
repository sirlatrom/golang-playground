package main

import (
	"crypto/tls"
	"crypto/x509"
	kpr "dumbserver/keypair_reloader"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
	})
	token, err := ioutil.ReadFile("/run/secrets/vault_token")
	if err != nil {
		panic(err)
	}
	log.Println("Read vault token")
	vaultConfig := vaultapi.DefaultConfig()
	vaultConfig.Address = "http://vault:8200"
	client, err := vaultapi.NewClient(vaultConfig)
	if err != nil {
		panic(err)
	}
	log.Println("Created Vault client")
	client.SetToken(string(token))
	params := make(map[string]interface{})
	params["common_name"] = "dumbserver"
	params["alt_names"] = "localhost"
	params["ttl"] = "1h"
	secret, err := client.Logical().Write("pki/issue/dumbserver", params)
	if err != nil {
		panic(err)
	}
	log.Println("Issued certs")
	renewer, err := client.NewRenewer(&vaultapi.RenewerInput{
		Secret: secret,
		Grace:  10 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	log.Println("Created renewer")
	go renewer.Renew()
	defer renewer.Stop()
	defer client.Sys().Revoke(secret.LeaseID)
	issuingCaContents := secret.Data["issuing_ca"].(string)
	certificateContents := secret.Data["certificate"].(string)
	ioutil.WriteFile("cert.pem", []byte(certificateContents), 0)
	privateKeyContents := secret.Data["private_key"].(string)
	ioutil.WriteFile("key.pem", []byte(privateKeyContents), 0)
	bundle := string(certificateContents) + string(issuingCaContents)
	ioutil.WriteFile("bundle.pem", []byte(bundle), 0)
	kpr, err := kpr.NewKeypairReloader("bundle.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Created keypair reloader")
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM([]byte(issuingCaContents)) {
		panic("Invalid CA")
	}
	log.Println("Loaded CA")
	tlsConfig := tls.Config{
		RootCAs: certPool,
	}
	tlsConfig.GetCertificate = kpr.GetCertificateFunc()
	srv := http.Server{
		Addr:      ":443",
		TLSConfig: &tlsConfig,
	}
	if err := srv.ListenAndServeTLS("bundle.pem", "key.pem"); err != nil {
		panic(err)
	}
	log.Println("Done serving")
}
