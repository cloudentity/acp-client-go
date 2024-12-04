// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/admin/client/a_c_rs"
	"github.com/cloudentity/acp-client-go/clients/admin/client/apis"
	"github.com/cloudentity/acp-client-go/clients/admin/client/audit_events"
	"github.com/cloudentity/acp-client-go/clients/admin/client/authorization_details"
	"github.com/cloudentity/acp-client-go/clients/admin/client/brute_force_limits"
	"github.com/cloudentity/acp-client-go/clients/admin/client/claims"
	"github.com/cloudentity/acp-client-go/clients/admin/client/clients"
	"github.com/cloudentity/acp-client-go/clients/admin/client/consents"
	"github.com/cloudentity/acp-client-go/clients/admin/client/custom_apps"
	"github.com/cloudentity/acp-client-go/clients/admin/client/environment"
	"github.com/cloudentity/acp-client-go/clients/admin/client/features"
	"github.com/cloudentity/acp-client-go/clients/admin/client/gateways"
	"github.com/cloudentity/acp-client-go/clients/admin/client/idps"
	"github.com/cloudentity/acp-client-go/clients/admin/client/images"
	"github.com/cloudentity/acp-client-go/clients/admin/client/keys"
	"github.com/cloudentity/acp-client-go/clients/admin/client/license"
	"github.com/cloudentity/acp-client-go/clients/admin/client/mfa_methods"
	"github.com/cloudentity/acp-client-go/clients/admin/client/openbanking"
	"github.com/cloudentity/acp-client-go/clients/admin/client/organizations"
	"github.com/cloudentity/acp-client-go/clients/admin/client/permissions"
	"github.com/cloudentity/acp-client-go/clients/admin/client/policies"
	"github.com/cloudentity/acp-client-go/clients/admin/client/recent_activities"
	"github.com/cloudentity/acp-client-go/clients/admin/client/roles"
	"github.com/cloudentity/acp-client-go/clients/admin/client/scopes"
	"github.com/cloudentity/acp-client-go/clients/admin/client/scripts"
	"github.com/cloudentity/acp-client-go/clients/admin/client/secrets"
	"github.com/cloudentity/acp-client-go/clients/admin/client/servers"
	"github.com/cloudentity/acp-client-go/clients/admin/client/services"
	"github.com/cloudentity/acp-client-go/clients/admin/client/system"
	"github.com/cloudentity/acp-client-go/clients/admin/client/templates"
	"github.com/cloudentity/acp-client-go/clients/admin/client/tenants"
	"github.com/cloudentity/acp-client-go/clients/admin/client/themes"
	"github.com/cloudentity/acp-client-go/clients/admin/client/tokens"
	"github.com/cloudentity/acp-client-go/clients/admin/client/vanity_domains"
	"github.com/cloudentity/acp-client-go/clients/admin/client/webhooks"
	"github.com/cloudentity/acp-client-go/clients/admin/client/workspaces"
)

// Default acp HTTP client.
var Default = NewHTTPClient(nil)

const (
	// DefaultHost is the default Host
	// found in Meta (info) section of spec file
	DefaultHost string = "localhost:8443"
	// DefaultBasePath is the default BasePath
	// found in Meta (info) section of spec file
	DefaultBasePath string = "/api/admin/default"
)

// DefaultSchemes are the default schemes found in Meta (info) section of spec file
var DefaultSchemes = []string{"https"}

// NewHTTPClient creates a new acp HTTP client.
func NewHTTPClient(formats strfmt.Registry) *Acp {
	return NewHTTPClientWithConfig(formats, nil)
}

// NewHTTPClientWithConfig creates a new acp HTTP client,
// using a customizable transport config.
func NewHTTPClientWithConfig(formats strfmt.Registry, cfg *TransportConfig) *Acp {
	// ensure nullable parameters have default
	if cfg == nil {
		cfg = DefaultTransportConfig()
	}

	// create transport and client
	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	return New(transport, formats)
}

// New creates a new acp client
func New(transport runtime.ClientTransport, formats strfmt.Registry) *Acp {
	// ensure nullable parameters have default
	if formats == nil {
		formats = strfmt.Default
	}

	cli := new(Acp)
	cli.Transport = transport
	cli.AcRs = a_c_rs.New(transport, formats)
	cli.Apis = apis.New(transport, formats)
	cli.AuditEvents = audit_events.New(transport, formats)
	cli.AuthorizationDetails = authorization_details.New(transport, formats)
	cli.BruteForceLimits = brute_force_limits.New(transport, formats)
	cli.Claims = claims.New(transport, formats)
	cli.Clients = clients.New(transport, formats)
	cli.Consents = consents.New(transport, formats)
	cli.CustomApps = custom_apps.New(transport, formats)
	cli.Environment = environment.New(transport, formats)
	cli.Features = features.New(transport, formats)
	cli.Gateways = gateways.New(transport, formats)
	cli.Idps = idps.New(transport, formats)
	cli.Images = images.New(transport, formats)
	cli.Keys = keys.New(transport, formats)
	cli.License = license.New(transport, formats)
	cli.MfaMethods = mfa_methods.New(transport, formats)
	cli.Openbanking = openbanking.New(transport, formats)
	cli.Organizations = organizations.New(transport, formats)
	cli.Permissions = permissions.New(transport, formats)
	cli.Policies = policies.New(transport, formats)
	cli.RecentActivities = recent_activities.New(transport, formats)
	cli.Roles = roles.New(transport, formats)
	cli.Scopes = scopes.New(transport, formats)
	cli.Scripts = scripts.New(transport, formats)
	cli.Secrets = secrets.New(transport, formats)
	cli.Servers = servers.New(transport, formats)
	cli.Services = services.New(transport, formats)
	cli.System = system.New(transport, formats)
	cli.Templates = templates.New(transport, formats)
	cli.Tenants = tenants.New(transport, formats)
	cli.Themes = themes.New(transport, formats)
	cli.Tokens = tokens.New(transport, formats)
	cli.VanityDomains = vanity_domains.New(transport, formats)
	cli.Webhooks = webhooks.New(transport, formats)
	cli.Workspaces = workspaces.New(transport, formats)
	return cli
}

// DefaultTransportConfig creates a TransportConfig with the
// default settings taken from the meta section of the spec file.
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		Host:     DefaultHost,
		BasePath: DefaultBasePath,
		Schemes:  DefaultSchemes,
	}
}

// TransportConfig contains the transport related info,
// found in the meta section of the spec file.
type TransportConfig struct {
	Host     string
	BasePath string
	Schemes  []string
}

// WithHost overrides the default host,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithHost(host string) *TransportConfig {
	cfg.Host = host
	return cfg
}

// WithBasePath overrides the default basePath,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithBasePath(basePath string) *TransportConfig {
	cfg.BasePath = basePath
	return cfg
}

// WithSchemes overrides the default schemes,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithSchemes(schemes []string) *TransportConfig {
	cfg.Schemes = schemes
	return cfg
}

// Acp is a client for acp
type Acp struct {
	AcRs a_c_rs.ClientService

	Apis apis.ClientService

	AuditEvents audit_events.ClientService

	AuthorizationDetails authorization_details.ClientService

	BruteForceLimits brute_force_limits.ClientService

	Claims claims.ClientService

	Clients clients.ClientService

	Consents consents.ClientService

	CustomApps custom_apps.ClientService

	Environment environment.ClientService

	Features features.ClientService

	Gateways gateways.ClientService

	Idps idps.ClientService

	Images images.ClientService

	Keys keys.ClientService

	License license.ClientService

	MfaMethods mfa_methods.ClientService

	Openbanking openbanking.ClientService

	Organizations organizations.ClientService

	Permissions permissions.ClientService

	Policies policies.ClientService

	RecentActivities recent_activities.ClientService

	Roles roles.ClientService

	Scopes scopes.ClientService

	Scripts scripts.ClientService

	Secrets secrets.ClientService

	Servers servers.ClientService

	Services services.ClientService

	System system.ClientService

	Templates templates.ClientService

	Tenants tenants.ClientService

	Themes themes.ClientService

	Tokens tokens.ClientService

	VanityDomains vanity_domains.ClientService

	Webhooks webhooks.ClientService

	Workspaces workspaces.ClientService

	Transport runtime.ClientTransport
}

// SetTransport changes the transport on the client and all its subresources
func (c *Acp) SetTransport(transport runtime.ClientTransport) {
	c.Transport = transport
	c.AcRs.SetTransport(transport)
	c.Apis.SetTransport(transport)
	c.AuditEvents.SetTransport(transport)
	c.AuthorizationDetails.SetTransport(transport)
	c.BruteForceLimits.SetTransport(transport)
	c.Claims.SetTransport(transport)
	c.Clients.SetTransport(transport)
	c.Consents.SetTransport(transport)
	c.CustomApps.SetTransport(transport)
	c.Environment.SetTransport(transport)
	c.Features.SetTransport(transport)
	c.Gateways.SetTransport(transport)
	c.Idps.SetTransport(transport)
	c.Images.SetTransport(transport)
	c.Keys.SetTransport(transport)
	c.License.SetTransport(transport)
	c.MfaMethods.SetTransport(transport)
	c.Openbanking.SetTransport(transport)
	c.Organizations.SetTransport(transport)
	c.Permissions.SetTransport(transport)
	c.Policies.SetTransport(transport)
	c.RecentActivities.SetTransport(transport)
	c.Roles.SetTransport(transport)
	c.Scopes.SetTransport(transport)
	c.Scripts.SetTransport(transport)
	c.Secrets.SetTransport(transport)
	c.Servers.SetTransport(transport)
	c.Services.SetTransport(transport)
	c.System.SetTransport(transport)
	c.Templates.SetTransport(transport)
	c.Tenants.SetTransport(transport)
	c.Themes.SetTransport(transport)
	c.Tokens.SetTransport(transport)
	c.VanityDomains.SetTransport(transport)
	c.Webhooks.SetTransport(transport)
	c.Workspaces.SetTransport(transport)
}
