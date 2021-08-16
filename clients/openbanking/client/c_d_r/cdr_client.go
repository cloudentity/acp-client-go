// Code generated by go-swagger; DO NOT EDIT.

package c_d_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new c d r API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for c d r API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	AcceptCDRArrangementSystem(params *AcceptCDRArrangementSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AcceptCDRArrangementSystemOK, error)

	CdrConsentIntrospect(params *CdrConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CdrConsentIntrospectOK, error)

	GetCDRArrangementSystem(params *GetCDRArrangementSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetCDRArrangementSystemOK, error)

	GetCDRArrangements(params *GetCDRArrangementsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetCDRArrangementsOK, error)

	ListCDRArrangements(params *ListCDRArrangementsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListCDRArrangementsOK, error)

	RejectCDRArrangementSystem(params *RejectCDRArrangementSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RejectCDRArrangementSystemOK, error)

	RevokeCDRArrangement(params *RevokeCDRArrangementParams, opts ...ClientOption) (*RevokeCDRArrangementNoContent, error)

	RevokeCDRArrangements(params *RevokeCDRArrangementsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeCDRArrangementsOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  AcceptCDRArrangementSystem accepts c d r arrangement

  This API can be used by a custom openbanking consent page to notify ACP that user accepted access.
*/
func (a *Client) AcceptCDRArrangementSystem(params *AcceptCDRArrangementSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AcceptCDRArrangementSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAcceptCDRArrangementSystemParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "acceptCDRArrangementSystem",
		Method:             "POST",
		PathPattern:        "/cdr/cdr-arrangement/{login}/accept",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AcceptCDRArrangementSystemReader{formats: a.formats},
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
	success, ok := result.(*AcceptCDRArrangementSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for acceptCDRArrangementSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  CdrConsentIntrospect introspects cdr consent

  This endpoint takes an OAuth 2.0 token and, in addition to returning
meta information surrounding the token, returns the cdr arrangement consent and
associated account ids.
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
  GetCDRArrangementSystem gets c d r arrangement

  This API can be used by a custom openbanking consent page.
The consent page must first use client credentials flow to create consent.
*/
func (a *Client) GetCDRArrangementSystem(params *GetCDRArrangementSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetCDRArrangementSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCDRArrangementSystemParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getCDRArrangementSystem",
		Method:             "GET",
		PathPattern:        "/cdr/cdr-arrangement/{login}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetCDRArrangementSystemReader{formats: a.formats},
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
	success, ok := result.(*GetCDRArrangementSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getCDRArrangementSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetCDRArrangements lists c d r arrangements

  This API returns the list of CDR arrangements.
You can narrow the list of returned arrangements using filters defined in request parameters.
See getCDRArrangements for details.
*/
func (a *Client) GetCDRArrangements(params *GetCDRArrangementsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetCDRArrangementsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCDRArrangementsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getCDRArrangements",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/cdr/arrangements",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetCDRArrangementsReader{formats: a.formats},
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
	success, ok := result.(*GetCDRArrangementsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getCDRArrangements: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListCDRArrangements lists c d r arrangements

  This API returns the list of CDR arrangements.
You can narrow the list of returned arrangements using filters defined in request body.
See listCDRArrangements for details.
*/
func (a *Client) ListCDRArrangements(params *ListCDRArrangementsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListCDRArrangementsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListCDRArrangementsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listCDRArrangements",
		Method:             "POST",
		PathPattern:        "/servers/{wid}/cdr/arrangements",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListCDRArrangementsReader{formats: a.formats},
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
	success, ok := result.(*ListCDRArrangementsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listCDRArrangements: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RejectCDRArrangementSystem rejects c d r arrangement

  This API can be used by a custom openbanking consent page to notify ACP that user rejected access.
*/
func (a *Client) RejectCDRArrangementSystem(params *RejectCDRArrangementSystemParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RejectCDRArrangementSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRejectCDRArrangementSystemParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "rejectCDRArrangementSystem",
		Method:             "POST",
		PathPattern:        "/cdr/cdr-arrangement/{login}/reject",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RejectCDRArrangementSystemReader{formats: a.formats},
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
	success, ok := result.(*RejectCDRArrangementSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for rejectCDRArrangementSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RevokeCDRArrangement thes c d r arrangement revocation endpoint

  Supports revocation of CDR arrangement.
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

/*
  RevokeCDRArrangements revokes c d r arrangements

  This API revokes CDR arrangements matching provided parameters.

Currently supporting removal by client id.
Use ?client_id={clientID} to remove all arrangements by a given client.
*/
func (a *Client) RevokeCDRArrangements(params *RevokeCDRArrangementsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeCDRArrangementsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeCDRArrangementsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeCDRArrangements",
		Method:             "DELETE",
		PathPattern:        "/servers/{wid}/cdr/arrangements",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeCDRArrangementsReader{formats: a.formats},
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
	success, ok := result.(*RevokeCDRArrangementsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeCDRArrangements: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}