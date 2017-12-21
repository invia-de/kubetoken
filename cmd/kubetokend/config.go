package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"github.com/atlassian/kubetoken"
	"github.com/pkg/errors"
)

type Environment struct {
	Name        string `json:"name"`
	Customer    string `json:"customer"`
	Environment string `json:"env"`
	caCertPEM   []byte // contents of the CAcert file, as PEM.
	Contexts    []struct {
		CACert           string            `json:"cacert"`  // path to ca cert
		PrivKey          string            `json:"privkey"` // path to ca cert private key
		caCertPEM        []byte            // contents of the CAcert file, as PEM.
		Clusters         map[string]string `json:"clusters"`
		kubetoken.Signer `json:"-"`
	} `json:"contexts"`
}

//type LDAP struct {
//	host	string		`json:"host"`
//	port	int		`json:"port"`
//	searchBase	string		`json:"search_base_dns"`
//	bindDN	string	`json:"bind_dn"`
//	bindPassword	string	`json:"bind_password"`
//	searchFilter	string	`json:"search_filter"`
//	groupSearchFilter		string	`json:"group_search_filter"`
//	groupSearchBaseDns	string	`json:"group_search_base_dns"`
//}

//type Config struct {
//	Environments []Environment `json:"environments"`
//	LDAP `json:"ldap"`
//}
 type Config struct {

        LDAP struct {
				Host	string		`json:"host"`
				Port	int		`json:"port"`
				SearchBase	string		`json:"search_base_dns"`
				BindDN	string	`json:"bind_dn"`
				BindPassword	string	`json:"bind_password"`
				SearchFilter	string	`json:"search_filter"`
				GroupSearchFilter		string	`json:"group_search_filter"`
				GroupSearchBaseDns	string	`json:"group_search_base_dns"`
				SkipVerify	bool	`json:"skip_verify"`
        } `json:"ldap"`
		Environments []Environment `json:"environments"`
		Kubetokend struct {
			Listen	string	`json:"listen"`
			Proto	string	`json:"proto"`
			Certfile	string	`json:"certfile"`
			Keyfile		string	`json:"keyfile"`
			Logfile		string	`json:"logfile"`
		} `json:"kubetokend"`
}


func loadConfig(p string) (*Config, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var config Config
	dec := json.NewDecoder(f)
	if err := dec.Decode(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func loadCertificates(c *Config) error {
	for i := range c.Environments {
		e := &c.Environments[i]
		for j := range e.Contexts {
			ctx := &e.Contexts[j]
			caCertPEM, err := ioutil.ReadFile(ctx.CACert)
			if err != nil {
				return errors.WithMessage(err, ctx.CACert)
			}
			privKeyPEM, err := ioutil.ReadFile(ctx.PrivKey)
			if err != nil {
				return errors.WithMessage(err, ctx.PrivKey)
			}

			block, _ := pem.Decode(caCertPEM)
			if block == nil {
				return errors.Errorf("%v: pem decode caCertPEM failed", ctx.CACert)
			}
			ctx.Signer.Cert, err = x509.ParseCertificate(block.Bytes)
			ctx.caCertPEM = caCertPEM
			if err != nil {
				return err
			}

			block, _ = pem.Decode(privKeyPEM)
			if block == nil {
				return errors.Errorf("%v: pem decode privKeyPEM failed", ctx.PrivKey)
			}
			ctx.Signer.PrivKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
