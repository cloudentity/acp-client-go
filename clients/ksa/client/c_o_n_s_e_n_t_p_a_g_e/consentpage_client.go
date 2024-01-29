// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new c o n s e n t p a g e API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for c o n s e n t p a g e API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	AcceptKSAConsentSystem(params *AcceptKSAConsentSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AcceptKSAConsentSystemOK, error)

	GetKSAConsentSystem(params *GetKSAConsentSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetKSAConsentSystemOK, error)

	RejectKSAConsentSystem(params *RejectKSAConsentSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RejectKSAConsentSystemOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
AcceptKSAConsentSystem accepts k s a consent

This API can be used by a custom openbanking consent page to notify ACP that user granted consent to a customer data access.
*/
func (a *Client) AcceptKSAConsentSystem(params *AcceptKSAConsentSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AcceptKSAConsentSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAcceptKSAConsentSystemParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "acceptKSAConsentSystem",
		Method:             "POST",
		PathPattern:        "/ksa/consent/{login}/accept",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AcceptKSAConsentSystemReader{formats: a.formats},
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
	success, ok := result.(*AcceptKSAConsentSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for acceptKSAConsentSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetKSAConsentSystem gets k s a consent

	This API can be used by a custom openbanking consent page.

The consent page must first use client credentials flow to create consent.
*/
func (a *Client) GetKSAConsentSystem(params *GetKSAConsentSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetKSAConsentSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetKSAConsentSystemParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getKSAConsentSystem",
		Method:             "GET",
		PathPattern:        "/ksa/consent/{login}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetKSAConsentSystemReader{formats: a.formats},
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
	success, ok := result.(*GetKSAConsentSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getKSAConsentSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RejectKSAConsentSystem rejects k s a consent

This API can be used by a custom openbanking consent page to notify ACP that user rejected access.
*/
func (a *Client) RejectKSAConsentSystem(params *RejectKSAConsentSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RejectKSAConsentSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRejectKSAConsentSystemParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "rejectKSAConsentSystem",
		Method:             "POST",
		PathPattern:        "/ksa/consent/{login}/reject",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RejectKSAConsentSystemReader{formats: a.formats},
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
	success, ok := result.(*RejectKSAConsentSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for rejectKSAConsentSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
