// Code generated by go-swagger; DO NOT EDIT.

package post_authn

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new post authn API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new post authn API client with basic auth credentials.
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

// New creates a new post authn API client with a bearer token for authentication.
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
Client for post authn API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	AbortPostAuthnRequest(params *AbortPostAuthnRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AbortPostAuthnRequestOK, error)

	CompletePostAuthnRequest(params *CompletePostAuthnRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CompletePostAuthnRequestOK, error)

	GetPostAuthnRequest(params *GetPostAuthnRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPostAuthnRequestOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
AbortPostAuthnRequest aborts post authn request

This API is used by a postAuthn page to notify ACP that postAuthn has been aborted.
*/
func (a *Client) AbortPostAuthnRequest(params *AbortPostAuthnRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AbortPostAuthnRequestOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAbortPostAuthnRequestParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "abortPostAuthnRequest",
		Method:             "POST",
		PathPattern:        "/post-authn/{login}/abort",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AbortPostAuthnRequestReader{formats: a.formats},
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
	success, ok := result.(*AbortPostAuthnRequestOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for abortPostAuthnRequest: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CompletePostAuthnRequest completes post authn request

This API is used by a postAuthn page to notify ACP that postAuthn has been successfully stored.
*/
func (a *Client) CompletePostAuthnRequest(params *CompletePostAuthnRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CompletePostAuthnRequestOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCompletePostAuthnRequestParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "completePostAuthnRequest",
		Method:             "POST",
		PathPattern:        "/post-authn/{login}/complete",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CompletePostAuthnRequestReader{formats: a.formats},
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
	success, ok := result.(*CompletePostAuthnRequestOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for completePostAuthnRequest: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetPostAuthnRequest gets post authn request

This API is used by a postAuthn page to make a decision if user should post authn.
*/
func (a *Client) GetPostAuthnRequest(params *GetPostAuthnRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPostAuthnRequestOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPostAuthnRequestParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getPostAuthnRequest",
		Method:             "GET",
		PathPattern:        "/post-authn/{login}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetPostAuthnRequestReader{formats: a.formats},
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
	success, ok := result.(*GetPostAuthnRequestOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getPostAuthnRequest: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
