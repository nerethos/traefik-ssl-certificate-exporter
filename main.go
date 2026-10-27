package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"rafi0101/traefik-ssl-certificate-exporter/models"
	"strings"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {

	// pflag.String("certResolver", "dode", "Acme certresolver to extract these certs (requiered)")
	pflag.String("source", "traefik/acme.json", "path to traefik acme.json")
	pflag.String("dest", "certs/", "path to destination where to store certificates")
	pflag.Int("owner", 0, "owner for the extracted cert/keys")
	pflag.Int("group", 0, "group for the extracted cert/keys")
	pflag.Bool("pfx", false, "also export cert.pfx (PKCS#12) containing key, cert and chain")
	pflag.String("pfx-password", "", "password for the exported cert.pfx")

	pflag.String("config", "", "Path to config file")

	pflag.Usage = func() {
		fmt.Println("traefik-ssl-certificate-exporter exports the ssl certificates from the provided traefik acme.json")
		pflag.PrintDefaults()
		os.Exit(0)
	}
	pflag.Parse()

	viper.BindPFlags(pflag.CommandLine)
	viper.SetConfigFile(viper.GetString("config"))

	viper.ReadInConfig()

	ownerId := viper.GetInt("owner")
	groupId := viper.GetInt("group")

	acmejson, err := ioutil.ReadFile(viper.GetString("source"))
	if err != nil {
		fmt.Println("Failed to read traefik acme.json", err)
		os.Exit(1)
	}

	// //Unmarshal traefik acme.json
	acme := new(models.ProviderMdl)
	if err := json.Unmarshal(acmejson, acme); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	//For each certificateprovider
	for _, certifcateProviderValue := range *acme {

		//For each certificate within one provider
		for _, certificate := range certifcateProviderValue.Certificates {

			//Get cert destination folder path, and replace * (Wildcard) with "_"
			certPath := viper.GetString("dest") + strings.Replace(certificate.Domain.Main, "*", "_", -1) + "/"
			os.MkdirAll(certPath, 0755)
			os.Chown(certPath, ownerId, groupId)

			//Decode private key
			privateKey, err := base64.StdEncoding.DecodeString(certificate.Key)
			if err != nil {
				fmt.Println("Failed to decode private key for ", certificate.Domain.Main, " :", err)
				os.Exit(1)
			}
			//Decode fullChain cert
			fullChain, err := base64.StdEncoding.DecodeString(certificate.Certificate)
			if err != nil {
				fmt.Println("Failed to decode fullchain for ", certificate.Domain.Main, " :", err)
				os.Exit(1)
			}

			//Convert fullChain []byte to string
			fullChainString := string(fullChain)

			//Get Index where cert ends and chain begins
			fullChainIndex := strings.Index(fullChainString, "\n-----BEGIN CERTIFICATE-----")

			if fullChainIndex < 0 {
				fmt.Println("Could not read fullchain cert")
				os.Exit(1)
			}
			//Cert we need is on top of the file. chain is everything else
			cert := fullChainString[:fullChainIndex]
			chain := fullChainString[fullChainIndex+1:]

			files := []struct {
				name string
				data []byte
				perm os.FileMode
			}{
				{"privkey.pem", privateKey, 0600},
				{"fullchain.pem", fullChain, 0644},
				{"cert.pem", []byte(cert), 0644},
				{"chain.pem", []byte(chain), 0644},
			}

			for _, file := range files {
				if err := writeIfChanged(certPath+file.name, file.data, file.perm, ownerId, groupId); err != nil {
					fmt.Println("Failed to write ", file.name, " for ", certificate.Domain.Main, " :", err)
					os.Exit(1)
				}
			}

			if viper.GetBool("pfx") {
				if err := writePfx(certPath+"cert.pfx", privateKey, fullChain, viper.GetString("pfx-password"), ownerId, groupId); err != nil {
					fmt.Println("Failed to write cert.pfx for ", certificate.Domain.Main, " :", err)
					os.Exit(1)
				}
			}

		}
	}

}

// writeIfChanged writes data to path, replacing any previous content.
// If the file already holds identical data it won't be touched.
func writeIfChanged(path string, data []byte, perm os.FileMode, ownerId, groupId int) error {
	old, err := ioutil.ReadFile(path)
	if err == nil && bytes.Equal(old, data) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := ioutil.WriteFile(path, data, perm); err != nil {
		return err
	}
	os.Chown(path, ownerId, groupId)
	return nil
}

// writePfx writes key and fullChain as a PKCS#12 bundle to path.
// PKCS#12 encoding is randomised, so instead of comparing bytes the existing
// file is kept if it opens with password and holds the same certificates.
func writePfx(path string, keyPem, fullChainPem []byte, password string, ownerId, groupId int) error {
	key, err := parsePrivateKey(keyPem)
	if err != nil {
		return err
	}

	var certs []*x509.Certificate
	for rest := fullChainPem; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return errors.New("no certificate found in fullchain")
	}

	if old, err := ioutil.ReadFile(path); err == nil {
		if _, oldCert, oldCaCerts, err := pkcs12.DecodeChain(old, password); err == nil && sameCerts(append([]*x509.Certificate{oldCert}, oldCaCerts...), certs) {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	pfx, err := pkcs12.LegacyDES.Encode(key, certs[0], certs[1:], password)
	if err != nil {
		return err
	}
	return writeIfChanged(path, pfx, 0600, ownerId, groupId)
}

// parsePrivateKey parses a PEM encoded RSA or EC private key in PKCS#1, SEC 1 or PKCS#8 form.
func parsePrivateKey(keyPem []byte) (interface{}, error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

func sameCerts(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
