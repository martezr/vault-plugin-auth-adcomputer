# vault-auth-plugin-adcomputer
HashiCorp Vault Active Directory Computer Auth Plugin


```
SHASUM=$(shasum -a 256 "/tmp/vault-plugins/vault-plugin-auth-adcomputer" | cut -d " " -f1)
```

```
vault write sys/plugins/catalog/auth/adcomputer-auth-plugin sha_256="$SHASUM" command="vault-plugin-auth-adcomputer"
```

```
vault auth enable -path=example -plugin-name=adcomputer-auth-plugin plugin
```

```
vault write auth/example/config ldap_server=grt.local ldap_port=389 bind_username=administrator bind_password=password
```

```
vault write auth/example/login computername=grtdc01 guid=FQPPPFEFE
```
