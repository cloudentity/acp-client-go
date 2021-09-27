// Code generated by go-swagger; DO NOT EDIT.

package openbanking_common

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new openbanking common API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for openbanking common API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	ConsumeOpenbankingConsent(params *ConsumeOpenbankingConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ConsumeOpenbankingConsentOK, error)

	GetOBConsents(params *GetOBConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetOBConsentsOK, error)

	ListOBConsents(params *ListOBConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListOBConsentsOK, error)

	RevokeOpenbankingConsent(params *RevokeOpenbankingConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeOpenbankingConsentNoContent, error)

	RevokeOpenbankingConsents(params *RevokeOpenbankingConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeOpenbankingConsentsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  ConsumeOpenbankingConsent consumes openbanking consent by ID

  This API consumes openbanking consent by consent id.
*/
func (a *Client) ConsumeOpenbankingConsent(params *ConsumeOpenbankingConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ConsumeOpenbankingConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewConsumeOpenbankingConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "consumeOpenbankingConsent",
		Method:             "POST",
		PathPattern:        "/api/system/{tid}/servers/{aid}/open-banking/consents/{consentID}/consume",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ConsumeOpenbankingConsentReader{formats: a.formats},
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
	success, ok := result.(*ConsumeOpenbankingConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for consumeOpenbankingConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetOBConsents gets openbanking consents

  This API returns the list of openbanking consents.
You can narrow the list of returned consents using filters defined in query parameters.
See GetConsentsParams for details.
*/
func (a *Client) GetOBConsents(params *GetOBConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetOBConsentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetOBConsentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getOBConsents",
		Method:             "GET",
		PathPattern:        "/api/system/{tid}/servers/{aid}/open-banking/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetOBConsentsReader{formats: a.formats},
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
	success, ok := result.(*GetOBConsentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getOBConsents: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListOBConsents lists openbanking consents

  This API returns the list of openbanking consents.
You can narrow the list of returned consents using filters defined in request body.
See ListConsentsParams for details.
*/
func (a *Client) ListOBConsents(params *ListOBConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListOBConsentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListOBConsentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listOBConsents",
		Method:             "POST",
		PathPattern:        "/api/system/{tid}/servers/{aid}/open-banking/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListOBConsentsReader{formats: a.formats},
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
	success, ok := result.(*ListOBConsentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listOBConsents: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RevokeOpenbankingConsent revokes openbanking consent by ID

  This API revokes openbanking consent by consent id.
*/
func (a *Client) RevokeOpenbankingConsent(params *RevokeOpenbankingConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeOpenbankingConsentNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeOpenbankingConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeOpenbankingConsent",
		Method:             "DELETE",
		PathPattern:        "/api/system/{tid}/servers/{aid}/open-banking/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeOpenbankingConsentReader{formats: a.formats},
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
	success, ok := result.(*RevokeOpenbankingConsentNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeOpenbankingConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RevokeOpenbankingConsents revokes openbanking consents

  This API revokes openbanking consents matching provided parameters.

Currently supporting removal by client id.
Use ?client_id={clientID} to remove all consents by a given client.

You can also optionally specify which consent should be removed by specifying consent type
example: ?client_id={clientID}&consent_type=account_access
*/
func (a *Client) RevokeOpenbankingConsents(params *RevokeOpenbankingConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeOpenbankingConsentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeOpenbankingConsentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeOpenbankingConsents",
		Method:             "DELETE",
		PathPattern:        "/api/system/{tid}/servers/{aid}/open-banking/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeOpenbankingConsentsReader{formats: a.formats},
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
	success, ok := result.(*RevokeOpenbankingConsentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeOpenbankingConsents: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
