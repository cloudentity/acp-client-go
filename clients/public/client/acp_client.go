// Code generated by go-swagger; DO NOT EDIT.

package client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/public/client/applications"
	"github.com/cloudentity/acp-client-go/clients/public/client/clients"
	"github.com/cloudentity/acp-client-go/clients/public/client/consents"
	"github.com/cloudentity/acp-client-go/clients/public/client/environment"
	"github.com/cloudentity/acp-client-go/clients/public/client/sessions"
	"github.com/cloudentity/acp-client-go/clients/public/client/tokens"
	"github.com/cloudentity/acp-client-go/clients/public/client/transient_otp"
)

// Default acp HTTP client.
var Default = NewHTTPClient(nil)

const (
	// DefaultHost is the default Host
	// found in Meta (info) section of spec file
	DefaultHost string = "localhost:8443"
	// DefaultBasePath is the default BasePath
	// found in Meta (info) section of spec file
	DefaultBasePath string = "/default/default"
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
	cli.Applications = applications.New(transport, formats)
	cli.Clients = clients.New(transport, formats)
	cli.Consents = consents.New(transport, formats)
	cli.Environment = environment.New(transport, formats)
	cli.Sessions = sessions.New(transport, formats)
	cli.Tokens = tokens.New(transport, formats)
	cli.TransientOtp = transient_otp.New(transport, formats)
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
	Applications applications.ClientService

	Clients clients.ClientService

	Consents consents.ClientService

	Environment environment.ClientService

	Sessions sessions.ClientService

	Tokens tokens.ClientService

	TransientOtp transient_otp.ClientService

	Transport runtime.ClientTransport
}

// SetTransport changes the transport on the client and all its subresources
func (c *Acp) SetTransport(transport runtime.ClientTransport) {
	c.Transport = transport
	c.Applications.SetTransport(transport)
	c.Clients.SetTransport(transport)
	c.Consents.SetTransport(transport)
	c.Environment.SetTransport(transport)
	c.Sessions.SetTransport(transport)
	c.Tokens.SetTransport(transport)
	c.TransientOtp.SetTransport(transport)
}
