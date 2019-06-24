package adcomputer

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"ldap_server": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "LDAP server hostname",
			},
			"ldap_port": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "LDAP server port",
			},
			"bind_username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Service URL (https://<tenant>.my.centrify.com)",
			},
			"bind_password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OAuth2 App ID",
			},
			"organizational_unit": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OAuth2 App Scope",
			},
			"policies": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of policies all authenticated users inherit",
			},
		},

		ExistenceCheck: b.pathConfigExistCheck,

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigCreateOrUpdate,
			logical.CreateOperation: b.pathConfigCreateOrUpdate,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis: pathSyn,
	}
}

func (b *backend) pathConfigExistCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return false, err
	}

	if config == nil {
		return false, nil
	}

	return true, nil
}

func (b *backend) pathConfigCreateOrUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if cfg == nil {
		cfg = &config{}
	}

	val, ok := data.GetOk("ldap_server")
	if ok {
		cfg.LdapServer = val.(string)
	} else if req.Operation == logical.CreateOperation {
		cfg.LdapServer = data.Get("ldap_server").(string)
	}
	if cfg.LdapServer == "" {
		return logical.ErrorResponse("config parameter `ldap_server` cannot be empty"), nil
	}

	val, ok = data.GetOk("ldap_port")
	if ok {
		cfg.LdapPort = val.(string)
	} else if req.Operation == logical.CreateOperation {
		cfg.LdapPort = data.Get("ldap_port").(string)
	}
	if cfg.LdapPort == "" {
		return logical.ErrorResponse("config parameter `ldap_port` cannot be empty"), nil
	}

	val, ok = data.GetOk("bind_username")
	if ok {
		cfg.BindUsername = val.(string)
	} else if req.Operation == logical.CreateOperation {
		cfg.BindUsername = data.Get("bind_username").(string)
	}
	if cfg.BindUsername == "" {
		return logical.ErrorResponse("config parameter `bind_username` cannot be empty"), nil
	}

  val, ok = data.GetOk("bind_password")
	if ok {
		cfg.BindPassword = val.(string)
	} else if req.Operation == logical.CreateOperation {
		cfg.BindPassword = data.Get("bind_password").(string)
	}
	if cfg.BindPassword == "" {
		return logical.ErrorResponse("config parameter `bind_password` cannot be empty"), nil
	}

	val, ok = data.GetOk("organizational_unit")
	if ok {
		cfg.OrganizationalUnit = val.(string)
	} else if req.Operation == logical.CreateOperation {
		cfg.OrganizationalUnit = data.Get("organizational_unit").(string)
	}

	val, ok = data.GetOk("policies")
	if ok {
		cfg.Policies = policyutil.ParsePolicies(val)
	} else if req.Operation == logical.CreateOperation {
		cfg.Policies = policyutil.ParsePolicies(data.Get("policies"))
	}

	// We want to normalize the service url to https://
	//url, err := url.Parse(cfg.ServiceURL)
	//if err != nil {
	//	return logical.ErrorResponse(fmt.Sprintf("config parameter 'service_url' is not a valid url: %s", err)), nil
	//}

	// Its a proper url, just force the scheme to https, and strip any paths
	//url.Scheme = "https"
	//url.Path = ""
	//cfg.ServiceURL = url.String()

	entry, err := logical.StorageEntryJSON("config", cfg)

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"ldap_server":         config.LdapServer,
			"ldap_port":           config.LdapPort,
			"bind_username":       config.BindUsername,
			"bind_password":       config.BindPassword,
      "organizational_unit": config.OrganizationalUnit,
			"policies":            config.Policies,
		},
	}
	return resp, nil
}

// Config returns the configuration for this backend.
func (b *backend) Config(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, "config")

	if err != nil {
		return nil, err
	}

	var result config
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
		return &result, nil
	}

	return nil, nil
}

type config struct {
	LdapServer         string   `json:"ldap_server"`
	LdapPort           string   `json:"ldap_port"`
	BindUsername       string   `json:"bind_username"`
	BindPassword       string   `json:"bind_password"`
	OrganizationalUnit string   `json:"organizational_unit"`
	Policies           []string `json:"policies"`
}

const pathConfigSyn = `
Provide Vault with the CA certificate used to issue all client certificates.
`

const pathConfigDesc = `
When a login is attempted using a PCF client certificate, Vault will verify
that the client certificate was issued by the CA certificate configured here.
Only those passing this check will be able to gain authorization.
`
