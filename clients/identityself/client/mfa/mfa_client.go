// Code generated by go-swagger; DO NOT EDIT.

package mfa

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new mfa API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for mfa API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteMFASession(params *DeleteMFASessionParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteMFASessionNoContent, error)

	ListUserMFASessions(params *ListUserMFASessionsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserMFASessionsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteMFASession deletes user m f a session
*/
func (a *Client) DeleteMFASession(params *DeleteMFASessionParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteMFASessionNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteMFASessionParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteMFASession",
		Method:             "DELETE",
		PathPattern:        "/v2/self/mfa/sessions/{mfaSessionID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteMFASessionReader{formats: a.formats},
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
	success, ok := result.(*DeleteMFASessionNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteMFASession: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListUserMFASessions lists user m f a sessions

user MFA sessions.
*/
func (a *Client) ListUserMFASessions(params *ListUserMFASessionsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserMFASessionsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUserMFASessionsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUserMFASessions",
		Method:             "GET",
		PathPattern:        "/v2/self/mfa/sessions",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUserMFASessionsReader{formats: a.formats},
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
	success, ok := result.(*ListUserMFASessionsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUserMFASessions: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
