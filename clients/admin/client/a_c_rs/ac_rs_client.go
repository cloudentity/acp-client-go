// Code generated by go-swagger; DO NOT EDIT.

package a_c_rs

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new a c rs API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new a c rs API client with basic auth credentials.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - user: user for basic authentication header.
// - password: password for basic authentication header.
func NewClientWithBasicAuth(host, basePath, scheme, user, password string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BasicAuth(user, password)
	return &Client{transport: transport, formats: strfmt.Default}
}

// New creates a new a c rs API client with a bearer token for authentication.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - bearerToken: bearer token for Bearer authentication header.
func NewClientWithBearerToken(host, basePath, scheme, bearerToken string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BearerToken(bearerToken)
	return &Client{transport: transport, formats: strfmt.Default}
}

/*
Client for a c rs API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateACR(params *CreateACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateACRCreated, error)

	DeleteACR(params *DeleteACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteACRNoContent, error)

	GetACR(params *GetACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetACROK, error)

	ListACRs(params *ListACRsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListACRsOK, error)

	UpdateACR(params *UpdateACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateACROK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateACR creates a c r

Creates a new ACR.
*/
func (a *Client) CreateACR(params *CreateACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateACRCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateACRParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createACR",
		Method:             "POST",
		PathPattern:        "/servers/{wid}/acrs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateACRReader{formats: a.formats},
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
	success, ok := result.(*CreateACRCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createACR: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteACR deletes a c r

Deletes the ACR.
*/
func (a *Client) DeleteACR(params *DeleteACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteACRNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteACRParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteACR",
		Method:             "DELETE",
		PathPattern:        "/servers/{wid}/acrs/{acrID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteACRReader{formats: a.formats},
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
	success, ok := result.(*DeleteACRNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteACR: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetACR gets a c r

Returns an ACR.
*/
func (a *Client) GetACR(params *GetACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetACROK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetACRParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getACR",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/acrs/{acrID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetACRReader{formats: a.formats},
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
	success, ok := result.(*GetACROK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getACR: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListACRs lists a c rs

List ACRs.
*/
func (a *Client) ListACRs(params *ListACRsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListACRsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListACRsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listACRs",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/acrs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListACRsReader{formats: a.formats},
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
	success, ok := result.(*ListACRsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listACRs: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateACR updates a c r

Updates the ACR.
*/
func (a *Client) UpdateACR(params *UpdateACRParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateACROK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateACRParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateACR",
		Method:             "PUT",
		PathPattern:        "/servers/{wid}/acrs/{acrID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateACRReader{formats: a.formats},
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
	success, ok := result.(*UpdateACROK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateACR: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
