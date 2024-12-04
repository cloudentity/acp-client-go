// Code generated by go-swagger; DO NOT EDIT.

package c_d_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new c d r API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new c d r API client with basic auth credentials.
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

// New creates a new c d r API client with a bearer token for authentication.
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
Client for c d r API
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
	CdrConsentIntrospect(params *CdrConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CdrConsentIntrospectOK, error)

	RefreshMetadata(params *RefreshMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RefreshMetadataOK, error)

	RevokeCDRArrangement(params *RevokeCDRArrangementParams, opts ...ClientOption) (*RevokeCDRArrangementNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	CdrConsentIntrospect introspects c d r arrangement

	Accepts a refresh token and returns meta information surrounding the OAuth 2.0 refresh token along with the

CDR arrangement.

As per CDR regulations, Access Tokens and ID Tokens are unavailable for introspection.

The response includes:

`exp` a token expiration timestamp.

`scope` a space-separated list of scopes associated with the token.

`cdr_arrangement_id` a unique identifier of the arrangement.

`cdr_arrangement` an object holding the arrangement details.

`cdr_register_client_metadata` metadata from the CDR Register, including the Data Recipient and Software Product

statuses.
*/
func (a *Client) CdrConsentIntrospect(params *CdrConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CdrConsentIntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCdrConsentIntrospectParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "cdrConsentIntrospect",
		Method:             "POST",
		PathPattern:        "/cdr/consents/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CdrConsentIntrospectReader{formats: a.formats},
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
	success, ok := result.(*CdrConsentIntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for cdrConsentIntrospect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RefreshMetadata refreshes a d r metadata

	Indicate that a critical update to the metadata for Accredited Data Recipients has been made

and should be obtained. This endpoint is used by the CDR Register.

Supported version(s) of this endpoint: [1]
*/
func (a *Client) RefreshMetadata(params *RefreshMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RefreshMetadataOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRefreshMetadataParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "refreshMetadata",
		Method:             "POST",
		PathPattern:        "/admin/register/metadata",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RefreshMetadataReader{formats: a.formats},
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
	success, ok := result.(*RefreshMetadataOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for refreshMetadata: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RevokeCDRArrangement revokes c d r arrangement

	Withdraw a consent for an arrangement in compliance with the revocation endpoint defined by the Consumer

Data Standards specification. The operation is performed per client application.

This endpoint requires inline
[Private Key JWT](https://cloudentity.com/developers/basics/oauth-client-authentication/private-key-jwt-client-authentication/) authentication.
*/
func (a *Client) RevokeCDRArrangement(params *RevokeCDRArrangementParams, opts ...ClientOption) (*RevokeCDRArrangementNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeCDRArrangementParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeCDRArrangement",
		Method:             "POST",
		PathPattern:        "/arrangements/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeCDRArrangementReader{formats: a.formats},
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
	success, ok := result.(*RevokeCDRArrangementNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeCDRArrangement: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
