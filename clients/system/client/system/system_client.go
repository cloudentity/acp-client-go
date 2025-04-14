// Code generated by go-swagger; DO NOT EDIT.

package system

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new system API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for system API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GatewayExchange(params *GatewayExchangeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GatewayExchangeOK, error)

	GatewayIntrospect(params *GatewayIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GatewayIntrospectOK, error)

	RevokeTokens(params *RevokeTokensParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeTokensNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GatewayExchange exchanges token endpoint as a gateway
*/
func (a *Client) GatewayExchange(params *GatewayExchangeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GatewayExchangeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGatewayExchangeParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "gatewayExchange",
		Method:             "POST",
		PathPattern:        "/gateways/exchange",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GatewayExchangeReader{formats: a.formats},
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
	success, ok := result.(*GatewayExchangeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for gatewayExchange: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GatewayIntrospect introspects access token endpoint as a gateway
*/
func (a *Client) GatewayIntrospect(params *GatewayIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GatewayIntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGatewayIntrospectParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "gatewayIntrospect",
		Method:             "POST",
		PathPattern:        "/gateways/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GatewayIntrospectReader{formats: a.formats},
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
	success, ok := result.(*GatewayIntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for gatewayIntrospect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RevokeTokens revokes tokens

	This API can be utilized for one of the following purposes:

Revoke by consent ID**: If a `consent_id` is provided in the query parameter,
the tokens issued for that consent ID will be revoked. This option takes precedence
over subject-based revocation.

Subject-based revocation**: If no `consent_id` is provided, the API will revoke
tokens for the specified set of subjects provided in the body.

#Subject-based revocation:

Tokens will be revoked for the specified set of subjects, which can include access tokens,
refresh tokens, authorization codes, authorization requests, SSO sessions, and scope grants.

Additionally, if an optional `idp_id` is provided, the subject values will be recalculated
if the server is using hashed subject types.
*/
func (a *Client) RevokeTokens(params *RevokeTokensParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeTokensNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeTokensParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeTokens",
		Method:             "DELETE",
		PathPattern:        "/servers/{wid}/tokens",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeTokensReader{formats: a.formats},
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
	success, ok := result.(*RevokeTokensNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeTokens: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
