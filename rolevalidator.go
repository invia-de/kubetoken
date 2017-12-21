package kubetoken

import (
	"fmt"
	//"strings"
	ldap "gopkg.in/ldap.v2"
	"log"
)

// LDAPConn represents a LDAP connection that can handle search requests.
type LDAPConn interface {

	// Search performs a given search request.
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)

	// Close closes the connection and frees any associated requets.
	Close() // yes, ldap.v2 gets this wrong
}

// ADRoleValidater validates a user is permitted to assume a role
// as specified in Active Directory flavoured LDAP.
type ADRoleValidater struct {
	Bind func() (LDAPConn, error)
}
/*
func userdn(user string) string {
      return fmt.Sprintf(binddn(user), escapeDN(user))
}

func binddn(user string) string {
      if strings.HasSuffix(user, "-bot") {
              return "CN=%s,OU=bots,OU=people," + SearchBase
      }
      return "CN=%s,OU=people," + SearchBase
}
*/
func (r *ADRoleValidater) ValidateRoleForUser(user, role, groupSearchBaseDns, groupSearchFilter string) error {
	roledn := fmt.Sprintf("cn=%s,%s", escapeDN(role), groupSearchBaseDns)
	//filter := fmt.Sprintf("(&(objectCategory=Person)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:=%s))", roledn)
	filter := fmt.Sprintf(groupSearchFilter, escapeDN(user))

	kubeRoles := ldap.NewSearchRequest(
		roledn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"cn"},
		nil,
	)
	conn, err := r.Bind()
	if err != nil {
		return err
	}
	defer conn.Close()

	sr, err := conn.Search(kubeRoles)
	if err != nil {

		log.Println(fmt.Sprintf("Role Validate failed %s", err))
		return err
	}

	switch len(sr.Entries) {
	case 0:
		return fmt.Errorf("%s is not a member of %s", user, roledn)
	case 1:
		usercn := sr.Entries[0].GetAttributeValue("cn")
		if role != usercn {
			return fmt.Errorf("%q is not a member of %q; search returned %q", user, role, usercn)
		}
		return nil
	default:
		return fmt.Errorf("got %d entires for query %s: %s", len(sr.Entries), filter, sr.Entries)
	}

}
