// Code generated by go-swagger; DO NOT EDIT.

package b2_b_users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new b2 b users API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for b2 b users API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateB2BUser(params *CreateB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateB2BUserCreated, error)

	DeleteB2BUser(params *DeleteB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteB2BUserNoContent, error)

	GetB2BUser(params *GetB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetB2BUserOK, error)

	ListUsersB2B(params *ListUsersB2BParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUsersB2BOK, error)

	UpdateB2BUser(params *UpdateB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateB2BUserOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	CreateB2BUser creates b2 b user account

	Create a business user with extended data.

Any status and set of identifiers, addresses, and credentials are allowed.
If credential of type password is provided it can be marked as must_be_changed which forces user to change its password upon first login.

When no `payload_schema_id` are provided, the default values are taken from the
specified Identity Pool.

Payload and metadata must match the specified schema.

The response contains an extended view on user entry.

To retrieve a user entry without user creation, call the **Get B2B User Details** endpoint.
*/
func (a *Client) CreateB2BUser(params *CreateB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateB2BUserCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateB2BUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createB2BUser",
		Method:             "POST",
		PathPattern:        "/admin/b2b/pools/{ipID}/users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateB2BUserReader{formats: a.formats},
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
	success, ok := result.(*CreateB2BUserCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createB2BUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteB2BUser deletes b2 b user account

Remove a record about a business user account in the specified identity pool.
*/
func (a *Client) DeleteB2BUser(params *DeleteB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteB2BUserNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteB2BUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteB2BUser",
		Method:             "DELETE",
		PathPattern:        "/admin/b2b/pools/{ipID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteB2BUserReader{formats: a.formats},
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
	success, ok := result.(*DeleteB2BUserNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteB2BUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetB2BUser gets b2 b user details

	Retrieve extended information about a business user record.

The response contains business user's basic details, payload as well as all their identifiers,
addresses, and blurred credentials.
*/
func (a *Client) GetB2BUser(params *GetB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetB2BUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetB2BUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getB2BUser",
		Method:             "GET",
		PathPattern:        "/admin/b2b/pools/{ipID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetB2BUserReader{formats: a.formats},
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
	success, ok := result.(*GetB2BUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getB2BUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListUsersB2B lists b2 b users

	Retrieve the list of business users from the specified identity pool.

Results are sorted by user ID. No other sorting is supported.
*/
func (a *Client) ListUsersB2B(params *ListUsersB2BParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUsersB2BOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUsersB2BParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUsersB2B",
		Method:             "GET",
		PathPattern:        "/admin/b2b/pools/{ipID}/users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUsersB2BReader{formats: a.formats},
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
	success, ok := result.(*ListUsersB2BOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUsersB2B: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	UpdateB2BUser updates b2 b user record

	Update the basic set of business user data: payload, schemas, and status. Provide the required values for the fields

you need to update. Fields with no values are skipped for the update (not removed nor cleared).

The fields to be updated are overridden.

Any `payload` and `payload_schema_id` values passed must be mutually relevant.

To retrieve a business user entry without updating their record, call the **Get B2B User Details** endpoint.
*/
func (a *Client) UpdateB2BUser(params *UpdateB2BUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateB2BUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateB2BUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateB2BUser",
		Method:             "PUT",
		PathPattern:        "/admin/b2b/pools/{ipID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateB2BUserReader{formats: a.formats},
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
	success, ok := result.(*UpdateB2BUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateB2BUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
