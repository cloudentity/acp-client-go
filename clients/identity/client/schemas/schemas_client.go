// Code generated by go-swagger; DO NOT EDIT.

package schemas

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new schemas API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for schemas API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateSchema(params *CreateSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateSchemaCreated, error)

	DeleteSchema(params *DeleteSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteSchemaNoContent, error)

	GetSchema(params *GetSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetSchemaOK, error)

	ListSchemas(params *ListSchemasParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListSchemasOK, error)

	SystemGetSchema(params *SystemGetSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SystemGetSchemaOK, error)

	UpdateSchema(params *UpdateSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateSchemaOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateSchema creates schema

  Creates schema. If the `system` flag is set then that schema cannot be later deleted or modified.
*/
func (a *Client) CreateSchema(params *CreateSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateSchemaCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateSchemaParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createSchema",
		Method:             "POST",
		PathPattern:        "/admin/schemas",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateSchemaReader{formats: a.formats},
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
	success, ok := result.(*CreateSchemaCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createSchema: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteSchema deletes schema

  Deletes schema. It is not possible to delete schema marked as `system`.
*/
func (a *Client) DeleteSchema(params *DeleteSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteSchemaNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteSchemaParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteSchema",
		Method:             "DELETE",
		PathPattern:        "/admin/schemas/{schID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteSchemaReader{formats: a.formats},
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
	success, ok := result.(*DeleteSchemaNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteSchema: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetSchema gets schema

  Gets schema.
*/
func (a *Client) GetSchema(params *GetSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetSchemaOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSchemaParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getSchema",
		Method:             "GET",
		PathPattern:        "/admin/schemas/{schID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSchemaReader{formats: a.formats},
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
	success, ok := result.(*GetSchemaOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getSchema: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListSchemas lists schemas

  Lists schemas.
*/
func (a *Client) ListSchemas(params *ListSchemasParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListSchemasOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListSchemasParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listSchemas",
		Method:             "GET",
		PathPattern:        "/admin/schemas",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListSchemasReader{formats: a.formats},
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
	success, ok := result.(*ListSchemasOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listSchemas: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  SystemGetSchema gets schema

  Gets schema.
*/
func (a *Client) SystemGetSchema(params *SystemGetSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SystemGetSchemaOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSystemGetSchemaParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "systemGetSchema",
		Method:             "GET",
		PathPattern:        "/system/schemas/{schID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SystemGetSchemaReader{formats: a.formats},
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
	success, ok := result.(*SystemGetSchemaOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for systemGetSchema: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateSchema updates schema

  Updates schema. It is not possible to update schema marked as `system`.
*/
func (a *Client) UpdateSchema(params *UpdateSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateSchemaOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateSchemaParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateSchema",
		Method:             "PUT",
		PathPattern:        "/admin/schemas/{schID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateSchemaReader{formats: a.formats},
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
	success, ok := result.(*UpdateSchemaOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateSchema: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
