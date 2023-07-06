// Code generated by go-swagger; DO NOT EDIT.

package pools

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new pools API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for pools API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreatePool(params *CreatePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePoolCreated, error)

	CreateWorkspacePool(params *CreateWorkspacePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateWorkspacePoolCreated, error)

	DeletePool(params *DeletePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeletePoolNoContent, error)

	DeleteWorkspacePool(params *DeleteWorkspacePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteWorkspacePoolNoContent, error)

	GetPool(params *GetPoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPoolOK, error)

	ListMyWorkspacePools(params *ListMyWorkspacePoolsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListMyWorkspacePoolsOK, error)

	ListPools(params *ListPoolsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListPoolsOK, error)

	ListWorkspacePools(params *ListWorkspacePoolsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListWorkspacePoolsOK, error)

	UpdatePool(params *UpdatePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdatePoolOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	CreatePool creates identity pool

	Create an identity pool.

When no `metadata_schema_id` and/or `payload_schema_id` are provided in the request body, the identity pool
is created with the following defaults accordingly:

`default_metadata=metadata_v0`

`default_payload=user_v0`
*/
func (a *Client) CreatePool(params *CreatePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePoolCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreatePoolParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createPool",
		Method:             "POST",
		PathPattern:        "/admin/pools",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreatePoolReader{formats: a.formats},
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
	success, ok := result.(*CreatePoolCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createPool: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	CreateWorkspacePool creates identity pool for workspace

	Create an identity pool under the required workspace.

When no `metadata_schema_id` and/or `payload_schema_id` are provided in the request body, the identity pool
is created with the following defaults accordingly:

`default_metadata=metadata_v0`

`default_payload=user_v0`
*/
func (a *Client) CreateWorkspacePool(params *CreateWorkspacePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateWorkspacePoolCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateWorkspacePoolParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createWorkspacePool",
		Method:             "POST",
		PathPattern:        "/admin/workspace/{wid}/pools",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateWorkspacePoolReader{formats: a.formats},
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
	success, ok := result.(*CreateWorkspacePoolCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createWorkspacePool: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	DeletePool deletes identity pool

	Delete an identity pool. For this, provide the required identity pool identifier in the path.

To retrieve the identity pool ID, log in to the Admin workspace. Then go to Identity Providers >
[*click the connected identity provider name*] > Identity Pool > Manage Pool.
*/
func (a *Client) DeletePool(params *DeletePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeletePoolNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeletePoolParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deletePool",
		Method:             "DELETE",
		PathPattern:        "/admin/pools/{ipID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeletePoolReader{formats: a.formats},
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
	success, ok := result.(*DeletePoolNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deletePool: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteWorkspacePool deletes workspace identity pool

Delete a workspace identity pool.
*/
func (a *Client) DeleteWorkspacePool(params *DeleteWorkspacePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteWorkspacePoolNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteWorkspacePoolParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteWorkspacePool",
		Method:             "DELETE",
		PathPattern:        "/admin/workspace/{wid}/pools/{ipID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteWorkspacePoolReader{formats: a.formats},
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
	success, ok := result.(*DeleteWorkspacePoolNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteWorkspacePool: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetPool gets identity pool

	Retrieve detailed information about an identity pool. Pass the identifier of the required identity pool with the

`ipID` path parameter.

To retrieve the pool identifier, log in to the Admin workspace. Then go to Identity Providers >
[*click the connected identity provider name*] > Identity Pool > Manage Pool.
*/
func (a *Client) GetPool(params *GetPoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPoolOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPoolParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getPool",
		Method:             "GET",
		PathPattern:        "/admin/pools/{ipID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetPoolReader{formats: a.formats},
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
	success, ok := result.(*GetPoolOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getPool: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListMyWorkspacePools lists my workspace pools

	Retrieve the detailed information about identity pools connected to the workspace and available for the current

administrator.

Pass the required workspace identifier with the `wid` path parameter.

For administrator identification, pass the `if-match` header with the ETag as its value.
*/
func (a *Client) ListMyWorkspacePools(params *ListMyWorkspacePoolsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListMyWorkspacePoolsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListMyWorkspacePoolsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listMyWorkspacePools",
		Method:             "GET",
		PathPattern:        "/admin/workspace/{wid}/my/pools",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListMyWorkspacePoolsReader{formats: a.formats},
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
	success, ok := result.(*ListMyWorkspacePoolsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listMyWorkspacePools: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListPools lists identity pools

	Retrieve the list of identity pools available under the current administrator.

You can filter the response with the query parameters to narrow the pool list down.
*/
func (a *Client) ListPools(params *ListPoolsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListPoolsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListPoolsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listPools",
		Method:             "GET",
		PathPattern:        "/admin/pools",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListPoolsReader{formats: a.formats},
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
	success, ok := result.(*ListPoolsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listPools: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListWorkspacePools lists identity pools per workspace

	Retrieve the list of identity pools available for a workspace. Pass the required workspace identifier with the

`wid` path parameter.

You can filter the response with the query parameters to narrow the pool list down.
*/
func (a *Client) ListWorkspacePools(params *ListWorkspacePoolsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListWorkspacePoolsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListWorkspacePoolsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listWorkspacePools",
		Method:             "GET",
		PathPattern:        "/admin/workspace/{wid}/pools",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListWorkspacePoolsReader{formats: a.formats},
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
	success, ok := result.(*ListWorkspacePoolsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listWorkspacePools: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	UpdatePool updates identity pool

	Update the identity pool details. Pass the identifier of the required identity pool with the `ipID` path parameter.

To retrieve the identity pool ID, log in to the Admin workspace. Then go to Identity Providers >
[*click the connected identity provider name*] > Identity Pool > Manage Pool.
*/
func (a *Client) UpdatePool(params *UpdatePoolParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdatePoolOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdatePoolParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updatePool",
		Method:             "PUT",
		PathPattern:        "/admin/pools/{ipID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdatePoolReader{formats: a.formats},
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
	success, ok := result.(*UpdatePoolOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updatePool: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
