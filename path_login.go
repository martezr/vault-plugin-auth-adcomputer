package adcomputer

import (
	"context"
	"fmt"
	"strings"
  "log"

  "gopkg.in/ldap.v2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const sourceHeader string = "vault-plugin-auth-adcomputer"

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"computername": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The name of the computer account.",
			},
			"sid": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Computer account SID.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin,
			logical.AliasLookaheadOperation: b.pathLoginAliasLookahead,
		},

		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	computername := strings.ToLower(d.Get("computername").(string))
	if computername == "" {
		return nil, fmt.Errorf("missing computername")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: computername,
			},
		},
	}, nil
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
  // Load and validate auth method configuration
  config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("could not load configuration"), nil
	}

  // Validate username argument
	computername := strings.ToLower(d.Get("computername").(string))

  if computername == "" {
    return logical.ErrorResponse("missing computername"), nil
	}

  // Validate guid argument
  sid := strings.ToLower(d.Get("sid").(string))

	if sid == "" {
    return logical.ErrorResponse("missing sid"), nil
	}

  bindusername := config.BindUsername
  bindpassword := config.BindPassword
  ldapserver := config.LdapServer
  ldapport := config.LdapPort

  l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapserver, ldapport))
  if err != nil {
      return logical.ErrorResponse(err.Error()), nil
  }
  defer l.Close()

  // First bind with a read only user
  err = l.Bind(bindusername, bindpassword)
  if err != nil {
		return logical.ErrorResponse(err.Error()), nil
  }

  objectsid, name := GetMachineInfo(l, "dc=grt,dc=local", computername, sid)

	name = strings.ToLower(name)

  if computername != name {
    return logical.ErrorResponse("No matching computer account found"), nil
  }

	objectsid = fmt.Sprintf("%x", objectsid)
  if objectsid != sid {
    return logical.ErrorResponse("Mismatch SID"), nil
  }

	resp := &logical.Response{
		Auth: &logical.Auth{
			Policies: config.Policies,
			Metadata: map[string]string{
				"computername": computername,
			},
			DisplayName: computername,
			LeaseOptions: logical.LeaseOptions{
				TTL:       30,
				Renewable: false,
			},
			Alias: &logical.Alias{
				Name: computername,
			},
		},
	}

	return resp, nil
}

// Reference: Scott Sutherland (@_nullbind)
func GetMachineInfo(conn *ldap.Conn, baseDN string, computername string, sid string)(outsid, name string ) {

	attributes := []string{
		"name",
		"objectSid"}

  // TODO: Add computername to filter to find just the desired match
	filter := "(&(sAMAccountType=805306369))"
	sr := ldapSearch(baseDN, filter, attributes, conn)

  // FIRST: Check if the computer name provided exists within Active Directory
  if len(sr.Entries) != 1 {
      log.Fatal("Requested computer account does not exist")
  }

  // Fetch computer account GUID
  ldapSid := sr.Entries[0].GetAttributeValue("objectSid")
  fmt.Printf("Computer SID: %x \n", ldapSid)

  accountName := sr.Entries[0].GetAttributeValue("name")
  fmt.Printf("Computer Name: %s \n", accountName)

  return ldapSid, accountName
}

func ldapSearch(searchDN string, filter string, attributes []string, conn *ldap.Conn) *ldap.SearchResult {

	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := conn.SearchWithPaging(searchRequest, 200)
	if err != nil {
		log.Println(err)
	}

	return sr

}

const pathLoginSyn = `
Log in with a computername and sid.
`
const pathLoginDesc = `
This endpoint authenticates using computername and guid against a Microsoft Active Directory domain.
`
