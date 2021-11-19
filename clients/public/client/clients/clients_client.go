// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new clients API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for clients API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	ListClientsWithAccess(params *ListClientsWithAccessParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListClientsWithAccessOK, error)

	RevokeClientAccess(params *RevokeClientAccessParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeClientAccessNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  ListClientsWithAccess lists clients that user shared data with

  Each client contains list of scopes that user agreed to.
*/
func (a *Client) ListClientsWithAccess(params *ListClientsWithAccessParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListClientsWithAccessOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListClientsWithAccessParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listClientsWithAccess",
		Method:             "GET",
		PathPattern:        "/clients",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListClientsWithAccessReader{formats: a.formats},
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
	success, ok := result.(*ListClientsWithAccessOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listClientsWithAccess: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RevokeClientAccess revokes client access

  Upon removal client won't be able to use user data anymore.
*/
func (a *Client) RevokeClientAccess(params *RevokeClientAccessParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeClientAccessNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeClientAccessParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeClientAccess",
		Method:             "DELETE",
		PathPattern:        "/clients/{cid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeClientAccessReader{formats: a.formats},
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
	success, ok := result.(*RevokeClientAccessNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeClientAccess: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
