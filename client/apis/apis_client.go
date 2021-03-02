// Code generated by go-swagger; DO NOT EDIT.

package apis

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new apis API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for apis API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateAPI(params *CreateAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateAPICreated, error)

	DeleteAPI(params *DeleteAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteAPINoContent, error)

	GetAPI(params *GetAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIOK, error)

	ListAPIsByServer(params *ListAPIsByServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListAPIsByServerOK, error)

	ListAPIsByService(params *ListAPIsByServiceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListAPIsByServiceOK, error)

	UpdateAPI(params *UpdateAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateAPIOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateAPI creates API

  It is not possible to create APIs for a service with imported specification.
*/
func (a *Client) CreateAPI(params *CreateAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateAPICreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateAPIParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createAPI",
		Method:             "POST",
		PathPattern:        "/api/admin/{tid}/apis",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateAPIReader{formats: a.formats},
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
	success, ok := result.(*CreateAPICreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createAPI: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteAPI deletes API

  If this API was created by import specification operation then
it is not possible to delete it.
*/
func (a *Client) DeleteAPI(params *DeleteAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteAPINoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteAPIParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteAPI",
		Method:             "DELETE",
		PathPattern:        "/api/admin/{tid}/apis/{api}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteAPIReader{formats: a.formats},
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
	success, ok := result.(*DeleteAPINoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteAPI: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAPI gets API

  Get API.
*/
func (a *Client) GetAPI(params *GetAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAPIOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAPIParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getAPI",
		Method:             "GET",
		PathPattern:        "/api/admin/{tid}/apis/{api}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAPIReader{formats: a.formats},
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
	success, ok := result.(*GetAPIOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getAPI: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListAPIsByServer lists a p is

  List APIs.
*/
func (a *Client) ListAPIsByServer(params *ListAPIsByServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListAPIsByServerOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListAPIsByServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listAPIsByServer",
		Method:             "GET",
		PathPattern:        "/api/admin/{tid}/servers/{aid}/apis",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListAPIsByServerReader{formats: a.formats},
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
	success, ok := result.(*ListAPIsByServerOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listAPIsByServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListAPIsByService lists a p is

  List APIs.
*/
func (a *Client) ListAPIsByService(params *ListAPIsByServiceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListAPIsByServiceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListAPIsByServiceParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listAPIsByService",
		Method:             "GET",
		PathPattern:        "/api/admin/{tid}/services/{sid}/apis",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListAPIsByServiceReader{formats: a.formats},
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
	success, ok := result.(*ListAPIsByServiceOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listAPIsByService: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateAPI updates API

  Update API.
*/
func (a *Client) UpdateAPI(params *UpdateAPIParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateAPIOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateAPIParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateAPI",
		Method:             "PUT",
		PathPattern:        "/api/admin/{tid}/apis/{api}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateAPIReader{formats: a.formats},
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
	success, ok := result.(*UpdateAPIOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateAPI: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
