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

	SetTransport(transport runtime.ClientTransport)
}

/*
  GatewayExchange Exchange token endpoint as a gateway
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
  GatewayIntrospect Introspect access token endpoint as a gateway
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

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
