// Code generated by go-swagger; DO NOT EDIT.

package limits

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new limits API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for limits API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteRateLimit(params *DeleteRateLimitParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteRateLimitNoContent, error)

	ListRateLimits(params *ListRateLimitsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListRateLimitsOK, error)

	SetRateLimit(params *SetRateLimitParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetRateLimitNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteRateLimit deletes rate limit

Delete custom rate limit for a module per tenant.
*/
func (a *Client) DeleteRateLimit(params *DeleteRateLimitParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteRateLimitNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteRateLimitParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteRateLimit",
		Method:             "DELETE",
		PathPattern:        "/api/admin/tenants/{tid}/rate-limits/{module}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteRateLimitReader{formats: a.formats},
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
	success, ok := result.(*DeleteRateLimitNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteRateLimit: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListRateLimits lists rate limits

List custom rate limits per tenant.
*/
func (a *Client) ListRateLimits(params *ListRateLimitsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListRateLimitsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListRateLimitsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listRateLimits",
		Method:             "GET",
		PathPattern:        "/api/admin/tenants/{tid}/rate-limits",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListRateLimitsReader{formats: a.formats},
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
	success, ok := result.(*ListRateLimitsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listRateLimits: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SetRateLimit sets rate limit

Set custom rate limit for a module per tenant.
*/
func (a *Client) SetRateLimit(params *SetRateLimitParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetRateLimitNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetRateLimitParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setRateLimit",
		Method:             "PUT",
		PathPattern:        "/api/admin/tenants/{tid}/rate-limits/{module}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetRateLimitReader{formats: a.formats},
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
	success, ok := result.(*SetRateLimitNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setRateLimit: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
