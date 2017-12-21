# Installation

This page describes the steps necessary to customise kubetoken for your environment.

## Linker variables

To avoid the necessity for a configuration file to be distributed alongside kubetoken, the default value of the variables for 

- version string


are set to dummy values in the source.
When building `kubetoken` and `kubetokend` you may use the `-X` linker flag to overwrite those values with site specific values.

## DUO two factor authentication

Kubetoken supports 2fa via the DUO. This feature is disabled by default. To enable this feature set the following three flags in your kubetokend deployment

- `--duoikey` (defaults to `DUO_IKEY`)
- `--duoskey` (defaults to `DUO_SKEY`)
- `--duoapihost` (defaults to `DUO_API_HOST`)

All three values can be retrieved from the admin console by someone with Duo administration rights for your organisation.

## kubetoken cli

Once built, `kubetoken` can be distributed to your users as a single binary or with the Debian Package. 
It will use Environment Variables for $USER, $KUBETOKEN_SSO_AUTH_URL, $KUBETOKEN_PW.
The Credentials/Contexts of the Configuration in $HOME/.kube/config will be updated. 

## kubetokend deployment

If you are planning on deploying kubetoken inside kubernetes you will need to do the following.

1. Build and upload a Docker image of `kubetokend`. A sample [Dockerfile](DOCKERFILE.example) is provided in this repository.
2. Deploy `kubetokend` to your cluster. A sample [deployment manifest](deployment/) is provided in this repository. You will need to add secrets for each pair of CA certificate and private keys for each cluster you wish to use.
   ```
   kubectl create secret generic -n $NAMESPACE $NAME --from-file=ca.pem --from-file=ca-key.pem
   ```
## kubetokend deployment with Build Debian Package
 * Run 

```
dpkg -i pkg.deb
```

 * All configuration goes in /etc/kubetoken/kubetoken.json. 
 * A sample Configuration with lies [here](config/kubetoken.json.dist). You can configure all the static linked Variables from the original Kubetoken Github Project from Atlassian. 
 * We added those:

```
	"ldap": {
		"host":"ldaphost",
		"port":636,
		"search_base_dns":"dc=example,dc=lan",
		"bind_dn":"uid=serviceaccount,ou=Services,dc=example,dc=lan",
		"bind_password":"secret",
		"search_filter":"(uid=%s)",
		"group_search_filter":"(&(cn=kube-*)(objectClass=posixGroup)(memberUid=%s))",
		"group_search_base_dns":"ou=groups,dc=example,dc=lan",
		"skip_verify":false
 	},
	"kubetokend": {
		"listen":"0.0.0.0:443",
		"proto" : "https",
		"certfile" : "/etc/kubetoken/ssl/wildcard.pem",
		"keyfile" : "/etc/kubetoken/ssl/wildcard.key",
		"logfile" : "/var/log/kubetokend.log"
	},

```

 * Start the Service with systemctl start kubetokend.service
