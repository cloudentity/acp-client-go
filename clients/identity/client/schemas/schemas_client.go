// Code generated by go-swagger; DO NOT EDIT.

package schemas

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new schemas API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new schemas API client with basic auth credentials.
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

// New creates a new schemas API client with a bearer token for authentication.
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
Client for schemas API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateSchema(params *CreateSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateSchemaCreated, error)

	DeleteSchema(params *DeleteSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteSchemaNoContent, error)

	GetSchema(params *GetSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetSchemaOK, error)

	GetWorkspaceSchema(params *GetWorkspaceSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWorkspaceSchemaOK, error)

	ListSchemas(params *ListSchemasParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListSchemasOK, error)

	ListWorkspaceSchemas(params *ListWorkspaceSchemasParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListWorkspaceSchemasOK, error)

	UpdateSchema(params *UpdateSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateSchemaOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateSchema creates schema

Create a schema. Set the `system` flag to prevent the schema from deletion or modifications.
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

Delete a schema. Schemas marked with the `system` flag aren't available for deletion.
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

Retrieve information about a specified identity schema.
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
GetWorkspaceSchema gets workspace schema

Retrieve information about a specified identity schema.
*/
func (a *Client) GetWorkspaceSchema(params *GetWorkspaceSchemaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWorkspaceSchemaOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetWorkspaceSchemaParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getWorkspaceSchema",
		Method:             "GET",
		PathPattern:        "/admin/workspace/{wid}/schemas/{schID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetWorkspaceSchemaReader{formats: a.formats},
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
	success, ok := result.(*GetWorkspaceSchemaOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getWorkspaceSchema: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListSchemas lists schemas

List schemas available for the current administrator.
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
ListWorkspaceSchemas lists workspace schemas

List schemas available for the workspace.
*/
func (a *Client) ListWorkspaceSchemas(params *ListWorkspaceSchemasParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListWorkspaceSchemasOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListWorkspaceSchemasParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listWorkspaceSchemas",
		Method:             "GET",
		PathPattern:        "/admin/workspace/{wid}/schemas",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListWorkspaceSchemasReader{formats: a.formats},
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
	success, ok := result.(*ListWorkspaceSchemasOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listWorkspaceSchemas: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateSchema updates schema

Update a schema. Schemas marked with the `system` flag aren't available for update.
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
