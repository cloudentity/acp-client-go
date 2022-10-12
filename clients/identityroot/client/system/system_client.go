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
	SystemGenerateCode(params *SystemGenerateCodeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SystemGenerateCodeCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	SystemGenerateCode generates code of a specific type

	Generate code of a specific type for provided address

Invalidates previously generated OTPs for action associated with the type.
Code is valid for specific period of time configured in Identity Pool.

Keep in mind that `address` attribute for different code types does not mean the same:
for `reset_password` and `challenge` it must be user's address (verified or unverified)
for `activation` it is not mandatory (system will pick up address itself if there is only one in user entry) but if provided it must be one of the user's addresses (can be not verified)
for `verify_address` it must be user's unverified address and that address cannot be someone's else verified address

For `activation`, `reset_password` and `challenge` there is only one active code for a user (generating new one invalidates previous)
For `verify_address` there might be many codes for a user. During verification latest for an address is being compared.

REFACTORED: input field name has been changed from `identifier` to `address`; field `identifier` stays for backward compatibility and overrides `address` if not empty
*/
func (a *Client) SystemGenerateCode(params *SystemGenerateCodeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SystemGenerateCodeCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSystemGenerateCodeParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "systemGenerateCode",
		Method:             "POST",
		PathPattern:        "/code/generate",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SystemGenerateCodeReader{formats: a.formats},
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
	success, ok := result.(*SystemGenerateCodeCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for systemGenerateCode: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
