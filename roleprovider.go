package kubetoken

import (
	"bytes"
	"fmt"
	"log"

	ldap "gopkg.in/ldap.v2"
)

// ADRoleProvider speaks Active Directory flavoured LDAP to retrieve the
// roles available to a specific user.
type ADRoleProvider struct {
	LDAPCreds
}

func (r *ADRoleProvider) FetchRolesForUser(user, groupSearchBaseDns, groupSearchFilter string) ([]string, error) {
	return fetchRolesForUser(&r.LDAPCreds, user, groupSearchBaseDns, groupSearchFilter)
}

func fetchRolesForUser(creds *LDAPCreds, user string, groupSearchBaseDns string, groupSearchFilter string ) ([]string, error) {
	conn, err := creds.Bind()
	if err != nil {
		log.Println("failed Bind")
		return nil, err
	}
	defer conn.Close()


	// find all the kube- roles
//	filter := fmt.Sprintf("(&(cn=kube-*-*-*-dl-*)(member:1.2.840.113556.1.4.1941:=%s))", userdn)
	filter := fmt.Sprintf(groupSearchFilter, user)

	//log.Println(groupSearchBaseDns)

	kubeRoles := ldap.NewSearchRequest(
		groupSearchBaseDns,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"cn"},
		nil,
	)
	sr, err := conn.Search(kubeRoles)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	var roles []string
	for _, e := range sr.Entries {
		role := e.GetAttributeValue("cn")
		roles = append(roles, role)
	}
//	log.Println(roles)
	return roles, nil
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
