// Code generated by go-swagger; DO NOT EDIT.

package f_d_x

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new f d x API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new f d x API client with basic auth credentials.
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

// New creates a new f d x API client with a bearer token for authentication.
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
Client for f d x API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// This client is generated with a few options you might find useful for your swagger spec.
//
// Feel free to add you own set of options.

// WithContentType allows the client to force the Content-Type header
// to negotiate a specific Consumer from the server.
//
// You may use this option to set arbitrary extensions to your MIME media type.
func WithContentType(mime string) ClientOption {
	return func(r *runtime.ClientOperation) {
		r.ConsumesMediaTypes = []string{mime}
	}
}

// WithContentTypeApplicationJSON sets the Content-Type header to "application/json".
func WithContentTypeApplicationJSON(r *runtime.ClientOperation) {
	r.ConsumesMediaTypes = []string{"application/json"}
}

// WithContentTypeApplicationxWwwFormUrlencoded sets the Content-Type header to "application/x-www-form-urlencoded".
func WithContentTypeApplicationxWwwFormUrlencoded(r *runtime.ClientOperation) {
	r.ConsumesMediaTypes = []string{"application/x-www-form-urlencoded"}
}

// ClientService is the interface for Client methods
type ClientService interface {
	FdxConsentIntrospect(params *FdxConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*FdxConsentIntrospectOK, error)

	GetFDXConsent(params *GetFDXConsentParams, opts ...ClientOption) (*GetFDXConsentOK, error)

	GetFDXConsentRevocation(params *GetFDXConsentRevocationParams, opts ...ClientOption) (*GetFDXConsentRevocationOK, error)

	RevokeFDXConsent(params *RevokeFDXConsentParams, opts ...ClientOption) (*RevokeFDXConsentNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	FdxConsentIntrospect introspects f d x consent

	Accepts an OAuth 2.0 token and returns meta information surrounding the token along with the FDX consent.

Authorization: Bearer token.

To obtain a token, use the
[Authorization code](https://cloudentity.com/developers/basics/oauth-grant-types/authorization-code-flow/) grant type.
*/
func (a *Client) FdxConsentIntrospect(params *FdxConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*FdxConsentIntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewFdxConsentIntrospectParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "fdxConsentIntrospect",
		Method:             "POST",
		PathPattern:        "/fdx/consents/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &FdxConsentIntrospectReader{formats: a.formats},
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
	success, ok := result.(*FdxConsentIntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for fdxConsentIntrospect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetFDXConsent gets consent grant

Retrieve FDX consent grant data by the consent identifier.
*/
func (a *Client) GetFDXConsent(params *GetFDXConsentParams, opts ...ClientOption) (*GetFDXConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFDXConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getFDXConsent",
		Method:             "GET",
		PathPattern:        "/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetFDXConsentReader{formats: a.formats},
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
	success, ok := result.(*GetFDXConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getFDXConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetFDXConsentRevocation retrieves consent revocation record

	Retrieve the details about consent revocation by the consent identifier.

This endpoint returns the `404` response code when:

1. No consent with this ID exists.

2. The specified consent isn't revoked.
*/
func (a *Client) GetFDXConsentRevocation(params *GetFDXConsentRevocationParams, opts ...ClientOption) (*GetFDXConsentRevocationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetFDXConsentRevocationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getFDXConsentRevocation",
		Method:             "GET",
		PathPattern:        "/consents/{consentID}/revocation",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetFDXConsentRevocationReader{formats: a.formats},
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
	success, ok := result.(*GetFDXConsentRevocationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getFDXConsentRevocation: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RevokeFDXConsent revokes f d x consent

	Revoke a user's consent.

The `204` response indicates that the consent status is changed to `REVOKED`. The revocation `initiator` and `reason`
passed in the request body are saved.
*/
func (a *Client) RevokeFDXConsent(params *RevokeFDXConsentParams, opts ...ClientOption) (*RevokeFDXConsentNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeFDXConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeFDXConsent",
		Method:             "PUT",
		PathPattern:        "/consents/{consentID}/revocation",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeFDXConsentReader{formats: a.formats},
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
	success, ok := result.(*RevokeFDXConsentNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeFDXConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
