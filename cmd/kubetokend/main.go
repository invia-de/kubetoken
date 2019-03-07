// kubetokend handles requests for kubeconfig cert/key pairs.
// For the cli command, see kubetoken.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	//"strings"

	"github.com/atlassian/kubetoken"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	ldap "gopkg.in/ldap.v2"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

// this value can be overwritten by -ldflags="-X main.BindDN=$BIND_DN"
//var BindDN = "OU=people,DC=office,DC=atlassian,DC=com"

func main() {

	fmt.Println(os.Args[0], "version:", kubetoken.Version)

	duoIKey := kingpin.Flag("duoikey", "Duo ikey value (support disabled if not set)").Default(os.Getenv("DUO_IKEY")).String()
	duoSKey := kingpin.Flag("duoskey", "Duo skey value (support disabled if not set)").Default(os.Getenv("DUO_SKEY")).String()
	duoAPIHost := kingpin.Flag("duoapihost", "Duo API Host (support disabled if not set)").Default(os.Getenv("DUO_API_HOST")).String()

	configFile := kingpin.Flag("config", "path to kubetoken.json").Default("/config/kubetoken.json").String()
	kingpin.Parse()

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("could not load config: %v", err)
	}

	var f *os.File
	f = os.Stdout
	if config.Kubetokend.Logfile != "" {
		f, err = os.OpenFile(config.Kubetokend.Logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	log.Println("loaded config: ")
	b, err := json.MarshalIndent(config, "", "  ")
	check(err)
	log.Println(fmt.Sprintf("%s\n", b))
	//@TODO Errors if Parameter not in Config
	//	ldapHost := config.LDAP.host
	//	searchBase := config.LDAP.searchBase

	if err := loadCertificates(config); err != nil {
		log.Fatalf("could not load certificates: %v", err)
	}

	r := mux.NewRouter()
	signer := http.Handler(&CertificateSigner{
		Config: config,
	})

	// If Duo is enabled, redirect signcsr to a duo authenticated version
	// this lets the client detect this and print the appropriate message
	// before re-submitting.
	if *duoIKey != "" && *duoSKey != "" && *duoAPIHost != "" {
		fmt.Println("Duo support enabled, using api host:", *duoAPIHost)
		r.HandleFunc("/api/v1/signcsr", func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Location", "/api/v1/signcsr2fa")
			w.WriteHeader(399)
		})
		r.Handle("/api/v1/signcsr2fa", BasicAuth(DuoAuth(signer, *duoIKey, *duoSKey, *duoAPIHost)))
	} else {
		r.Handle("/api/v1/signcsr", BasicAuth(signer))
	}
	r.Handle("/api/v1/roles", BasicAuth(&RoleHandler{
		Config: config,
	}))
	r.HandleFunc("/healthcheck", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "OK")
	})
	r.HandleFunc("/version", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, kubetoken.Version)
	})

	loggedRouter := handlers.LoggingHandler(f, r)

	//addr := fmt.Sprintf(":%s", os.Getenv("PORT"))

	addr := config.Kubetokend.Listen
	log.Println("listening on", addr)
	//log.Println("ldaphost", config.LDAP.Host)
	if config.Kubetokend.Proto == "https" {
		_, err := os.Stat(config.Kubetokend.Keyfile)
		_, err2 := os.Stat(config.Kubetokend.Certfile)
		if !os.IsNotExist(err) && !os.IsNotExist(err2) {
			log.Fatal(http.ListenAndServeTLS(addr, config.Kubetokend.Certfile, config.Kubetokend.Keyfile, loggedRouter))
		} else {
			log.Fatal("No Certificates for Serving found")
		}
	} else {
		http.ListenAndServe(addr, loggedRouter)
	}
}

type CertificateSigner struct {
	kubetoken.Signer
	*Config
}

func userdn(ldapHost string, ldapPort int, ldapBind string, ldapPass string, searchBase string, searchFilter string, user string, skipVerify bool) string {
	//return fmt.Sprintf(binddn(ldapHost, ldapBind, ldapPass, SearchBase, user), escapeDN(user))
	return binddn(ldapHost, ldapPort, ldapBind, ldapPass, searchBase, searchFilter, user, skipVerify)
	//return fmt.Sprintf(binddn(user, searchBase), escapeDN(user))
}

func getuserbinddn(user, searchBase string) string {
	return fmt.Sprintf("uid=%s,ou=Users,"+searchBase, escapeDN(user))
}

func binddn(ldapHost string, ldapPort int, ldapBind string, ldapPassword string, searchBase string, searchFilter string, user string, skipVerify bool) string {
	config := tls.Config{
		ServerName:         ldapHost,
		InsecureSkipVerify: skipVerify,
	}

	conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", ldapHost, ldapPort), &config)
	if err != nil {
		log.Println(err)
		return "failed"
	}
	err = conn.Bind(ldapBind, ldapPassword)
	if err != nil {
		log.Println(fmt.Sprintf("Fehler bei User %s: %s", user, err))
		return "failed"
	}
	defer conn.Close()
	log.Println(fmt.Sprintf("%s logged in", user))
	filter := fmt.Sprintf(searchFilter, user)

	userRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)
	sr, err := conn.Search(userRequest)
	if err != nil {
		log.Println("failed search")
		return "failed"
	}

	bindDN := ""

	if len(sr.Entries) > 0 {
		bindDN = sr.Entries[0].DN
	}

	return bindDN
}

func BasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _, ok := req.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Authentication required", 401)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (s *CertificateSigner) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok {
		http.Error(w, "Forbidden", 403)
		return
	}

	csr, err := readCSR(req.Body)

	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	if user != csr.Subject.CommonName {
		http.Error(w, fmt.Sprintf("Subject.CommonName %q does not match auth username %q", csr.Subject.CommonName, user), 403)
		return
	}
	role := csr.Subject.Organization[0]

	dn := userdn(
		s.Config.LDAP.Host,
		s.Config.LDAP.Port,
		getuserbinddn(user, s.Config.LDAP.SearchBase),
		pass,
		s.Config.LDAP.SearchBase,
		s.Config.LDAP.SearchFilter,
		user,
		s.Config.LDAP.SkipVerify,
	)
	if dn != getuserbinddn(user, s.Config.LDAP.SearchBase) {
		http.Error(w, "Forbidden", 403)
		return
	}

	ad := kubetoken.ADRoleValidater{
		Bind: func() (kubetoken.LDAPConn, error) {
			ldapcreds := kubetoken.LDAPCreds{
				Host:       s.Config.LDAP.Host,
				Port:       s.Config.LDAP.Port,
				BindDN:     s.Config.LDAP.BindDN,
				Password:   s.Config.LDAP.BindPassword,
				SkipVerify: s.Config.LDAP.SkipVerify,
			}
			return ldapcreds.Bind()
		},
	}

	if err := ad.ValidateRoleForUser(
		user,
		role,
		s.Config.LDAP.GroupSearchBaseDns,
		s.Config.LDAP.GroupSearchFilter,
	); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}

	customer, ns, environ, err := parseCustomerNamespaceEnvFromRole(role)

	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), 404)
		return
	}

	// find customer/environemnt for role
	var env *Environment
	for i := range s.Config.Environments {
		e := &s.Config.Environments[i]
		if e.Customer == customer && e.Environment == environ {
			env = e
			break
		}
	}
	if env == nil {
		http.Error(w, fmt.Sprintf("%s: no known environment", role), 400)
		return
	}

	certPEM, err := env.Contexts[0].Sign(csr)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// to support older clients, we push the cluster addresses from the
	// first context.
	var addresses []string
	for _, v := range env.Contexts[0].Clusters {
		addresses = append(addresses, v)
	}

	// sort lexically in the hope that cell-0 comes before cell-1, etc.
	sort.Stable(sort.StringSlice(addresses))

	var contexts []kubetoken.Context
	for _, c := range env.Contexts {
		contexts = append(contexts, kubetoken.Context{
			Files: map[string][]byte{
				"ca.pem":                    c.caCertPEM,
				fmt.Sprintf("%s.pem", user): certPEM,
			},
			Clusters: c.Clusters,
		})
	}

	enc := json.NewEncoder(w)
	enc.Encode(kubetoken.CertificateResponse{
		Username: user,
		Role:     csr.Subject.Organization[0],
		Files: map[string][]byte{
			"ca.pem":                    env.Contexts[0].caCertPEM,
			fmt.Sprintf("%s.pem", user): certPEM,
		},
		Customer:    env.Customer,
		Addresses:   addresses,
		Environment: env.Environment,
		Namespace:   ns,
		Contexts:    contexts,
	})
	log.Printf("authorised %v to assume role %v", csr.Subject.CommonName, csr.Subject.Organization[0])
}

type RoleHandler struct {
	*Config
}

func (r *RoleHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	user, pass, ok := req.BasicAuth()
	if !ok {
		http.Error(w, "Forbidden", 403)
		return
	}

	dn := userdn(
		r.Config.LDAP.Host,
		r.Config.LDAP.Port,
		getuserbinddn(user, r.Config.LDAP.SearchBase),
		pass,
		r.Config.LDAP.SearchBase,
		r.Config.LDAP.SearchFilter,
		user,
		r.Config.LDAP.SkipVerify,
	)
	if dn != getuserbinddn(user, r.Config.LDAP.SearchBase) {
		http.Error(w, "Forbidden", 403)
		return
	}
	ad := &kubetoken.ADRoleProvider{
		LDAPCreds: kubetoken.LDAPCreds{
			Host: r.Config.LDAP.Host,
			Port: r.Config.LDAP.Port,
			//BindDN:   userdn(r.Config.LDAP.Host, r.Config.LDAP.Port, r.Config.LDAP.BindDN, r.Config.LDAP.BindPassword, r.Config.LDAP.SearchBase, r.Config.LDAP.SearchFilter, user, r.Config.LDAP.SkipVerify),
			//Password: pass,
			BindDN:     r.Config.LDAP.BindDN,
			Password:   r.Config.LDAP.BindPassword,
			SkipVerify: r.Config.LDAP.SkipVerify,
		},
	}
	roles, err := ad.FetchRolesForUser(user, r.Config.LDAP.GroupSearchBaseDns, r.Config.LDAP.GroupSearchFilter)
	if err != nil {
		//		log.Println("no roles for user found")
		http.Error(w, err.Error(), 403)
		return
	}

	enc := json.NewEncoder(w)
	enc.Encode(struct {
		User  string   `json:"user"`
		Roles []string `json:"roles"`
	}{
		User:  user,
		Roles: roles,
	})
}

func readCSR(r io.Reader) (*x509.CertificateRequest, error) {
	csrPEM, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, errors.New("unable to decode PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("expected CERTIFICATE REQUEST, got " + block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func parseCustomerNamespaceEnvFromRole(role string) (string, string, string, error) {

	//return "invia","default","kubetokend",nil

	re, err := regexp.Compile(`^kube-(?P<customer>\w+)-(?P<ns>\w+)-(?P<env>\w+)`)
	if strings.HasPrefix(role, "k8s") {
		re, err = regexp.Compile(`^k8s_(?P<customer>[[:alnum:]-]+)_(?P<ns>[[:alnum:]-]+)_(?P<env>[[:alnum:]-]+)`)
	}

	if err != nil {
		return "", "", "", err
	}
	m := re.FindStringSubmatch(role)
	if len(m) != 4 {
		return "", "", "", fmt.Errorf("no match for role %q", role)
	}
	var customer, ns, env string
	for i, name := range re.SubexpNames() {
		switch name {
		case "customer":
			customer = m[i]
		case "ns":
			ns = m[i]
		case "env":
			env = m[i]
		}
	}
	if customer == "" {
		return "", "", "", fmt.Errorf("customer not found in role %q", role)
	}
	if ns == "" {
		return "", "", "", fmt.Errorf("namespace not found in role %q", role)
	}
	if env == "" {
		return "", "", "", fmt.Errorf("environment not found in role %q", role)
	}
	return customer, ns, env, nil
}

// escapeDN returns a string with characters escaped to safely injected into a DN.
// Intended as a complement to ldap.EscapeFilter, which escapes ldap filter strings.
// Made with reference to https://www.owasp.org/index.php/LDAP_Injection_Prevention_Cheat_Sheet
// and http://www.rlmueller.net/CharactersEscaped.htm
func escapeDN(unsafe string) string {
	var buf bytes.Buffer
	for _, r := range unsafe {
		switch r {
		case '/', '\\', '#', ',', ';', '<', '>', '+', '=':
			buf.WriteRune('\\')
			fallthrough
		default:
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
