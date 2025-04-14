// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new o t p API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for o t p API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CompleteAddressVerification(params *CompleteAddressVerificationParams, opts ...ClientOption) (*CompleteAddressVerificationNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	CompleteAddressVerification completes address verification

	Completes unverified address verification by checking if code is valid or not.

Both address and code must be provided.
Fails if address is not user's address or is user's verified or is someone's verified address.
If the OTP is valid it is removed and a successful response is returned.
Endpoint is protected by Brute Force mechanism.

This endpoint requires special privileges and is disabled by default.
*/
func (a *Client) CompleteAddressVerification(params *CompleteAddressVerificationParams, opts ...ClientOption) (*CompleteAddressVerificationNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCompleteAddressVerificationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "completeAddressVerification",
		Method:             "POST",
		PathPattern:        "/self/address-verification/complete",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CompleteAddressVerificationReader{formats: a.formats},
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
	success, ok := result.(*CompleteAddressVerificationNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for completeAddressVerification: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
