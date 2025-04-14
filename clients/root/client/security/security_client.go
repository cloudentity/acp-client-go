// Code generated by go-swagger; DO NOT EDIT.

package security

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new security API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new security API client with basic auth credentials.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - user: user for basic authentication header.
// - password: password for basic authentication header.
func NewClientWithBasicAuth(host, basePath, scheme, user, password string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BasicAuth(user, password)
	return &Client{transport: transport, formats: strfmt.Default}
}

// New creates a new security API client with a bearer token for authentication.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - bearerToken: bearer token for Bearer authentication header.
func NewClientWithBearerToken(host, basePath, scheme, bearerToken string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BearerToken(bearerToken)
	return &Client{transport: transport, formats: strfmt.Default}
}

/*
Client for security API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetSecurity(params *GetSecurityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetSecurityOK, error)

	GetTenantSecurity(params *GetTenantSecurityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetTenantSecurityOK, error)

	SetTenantSecurity(params *SetTenantSecurityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetTenantSecurityNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetSecurity gets security

Returns default security configuration
*/
func (a *Client) GetSecurity(params *GetSecurityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetSecurityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSecurityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getSecurity",
		Method:             "GET",
		PathPattern:        "/api/admin/tenants/security",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSecurityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetSecurityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getSecurity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetTenantSecurity gets tenant security
*/
func (a *Client) GetTenantSecurity(params *GetTenantSecurityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetTenantSecurityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetTenantSecurityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getTenantSecurity",
		Method:             "GET",
		PathPattern:        "/api/admin/tenants/{tid}/security",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetTenantSecurityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetTenantSecurityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getTenantSecurity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SetTenantSecurity sets tenant security
*/
func (a *Client) SetTenantSecurity(params *SetTenantSecurityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetTenantSecurityNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetTenantSecurityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setTenantSecurity",
		Method:             "POST",
		PathPattern:        "/api/admin/tenants/{tid}/security",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetTenantSecurityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SetTenantSecurityNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setTenantSecurity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
