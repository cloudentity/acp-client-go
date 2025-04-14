// Code generated by go-swagger; DO NOT EDIT.

package groups

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new groups API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new groups API client with basic auth credentials.
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

// New creates a new groups API client with a bearer token for authentication.
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
Client for groups API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	AddUserToGroup(params *AddUserToGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AddUserToGroupNoContent, error)

	CreateGroup(params *CreateGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateGroupCreated, error)

	DeleteGroup(params *DeleteGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteGroupNoContent, error)

	GetGroup(params *GetGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetGroupOK, error)

	IsUserInGroup(params *IsUserInGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*IsUserInGroupNoContent, error)

	ListGroups(params *ListGroupsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListGroupsOK, error)

	ListUserGroups(params *ListUserGroupsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserGroupsOK, error)

	ListUsersInGroup(params *ListUsersInGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUsersInGroupOK, error)

	RemoveUserFromGroup(params *RemoveUserFromGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RemoveUserFromGroupNoContent, error)

	UpdateGroup(params *UpdateGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateGroupOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
AddUserToGroup adds user to a specific group
*/
func (a *Client) AddUserToGroup(params *AddUserToGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AddUserToGroupNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAddUserToGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "addUserToGroup",
		Method:             "PUT",
		PathPattern:        "/system/pools/{ipID}/groups/{groupID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AddUserToGroupReader{formats: a.formats},
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
	success, ok := result.(*AddUserToGroupNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for addUserToGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateGroup creates group
*/
func (a *Client) CreateGroup(params *CreateGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateGroupCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createGroup",
		Method:             "POST",
		PathPattern:        "/system/pools/{ipID}/groups",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateGroupReader{formats: a.formats},
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
	success, ok := result.(*CreateGroupCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteGroup deletes group

Delete a group.
*/
func (a *Client) DeleteGroup(params *DeleteGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteGroupNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteGroup",
		Method:             "DELETE",
		PathPattern:        "/system/pools/{ipID}/groups/{groupID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteGroupReader{formats: a.formats},
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
	success, ok := result.(*DeleteGroupNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetGroup gets group details

Retrieve a group details.
*/
func (a *Client) GetGroup(params *GetGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetGroupOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getGroup",
		Method:             "GET",
		PathPattern:        "/system/pools/{ipID}/groups/{groupID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetGroupReader{formats: a.formats},
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
	success, ok := result.(*GetGroupOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	IsUserInGroup checks if user is in group

	Checks if user is in the group.

Fails with 404 if user is not in the group.
If query param with_nested_groups is set to true, it will check if user is in requested group or any nested group.
*/
func (a *Client) IsUserInGroup(params *IsUserInGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*IsUserInGroupNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIsUserInGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "isUserInGroup",
		Method:             "GET",
		PathPattern:        "/system/pools/{ipID}/users/{userID}/groups/{groupID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IsUserInGroupReader{formats: a.formats},
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
	success, ok := result.(*IsUserInGroupNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for isUserInGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListGroups lists groups

	Retrieve the top level list of groups from the specified identity pool.

If query param parent_id is set, the response will contain top level list of groups that are children of the specified group.

If query param with_nested_groups is set to true, the response will contain a list of groups with all nested groups (also nested groups of nested groups etc.)

Results are sorted by group `name`. No other sorting is supported.
*/
func (a *Client) ListGroups(params *ListGroupsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListGroupsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listGroups",
		Method:             "GET",
		PathPattern:        "/system/pools/{ipID}/groups",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListGroupsReader{formats: a.formats},
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
	success, ok := result.(*ListGroupsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListUserGroups lists user groups

	Retrieve the list of groups that user belongs to.

If query param with_parent_groups is set to true, the response will contain a list of groups and all parent groups

Results are sorted by group `name`. No other sorting is supported.
*/
func (a *Client) ListUserGroups(params *ListUserGroupsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserGroupsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUserGroupsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUserGroups",
		Method:             "GET",
		PathPattern:        "/system/pools/{ipID}/users/{userID}/groups",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUserGroupsReader{formats: a.formats},
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
	success, ok := result.(*ListUserGroupsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUserGroups: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListUsersInGroup lists users in group

	Retrieve the list of users under specific group.

If query param with_nested_groups is set to true, the response will contain a list of users in that group and all nested groups

Results are sorted by user ID. No other sorting is supported.

This endpoint follows eventual consistency and may temporarily omit newly created users under high load.
*/
func (a *Client) ListUsersInGroup(params *ListUsersInGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUsersInGroupOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUsersInGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUsersInGroup",
		Method:             "GET",
		PathPattern:        "/system/pools/{ipID}/groups/{groupID}/users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUsersInGroupReader{formats: a.formats},
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
	success, ok := result.(*ListUsersInGroupOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUsersInGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RemoveUserFromGroup removes user from group
*/
func (a *Client) RemoveUserFromGroup(params *RemoveUserFromGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RemoveUserFromGroupNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRemoveUserFromGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "removeUserFromGroup",
		Method:             "DELETE",
		PathPattern:        "/system/pools/{ipID}/groups/{groupID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RemoveUserFromGroupReader{formats: a.formats},
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
	success, ok := result.(*RemoveUserFromGroupNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for removeUserFromGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateGroup updates group
*/
func (a *Client) UpdateGroup(params *UpdateGroupParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateGroupOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateGroupParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateGroup",
		Method:             "PUT",
		PathPattern:        "/system/pools/{ipID}/groups/{groupID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateGroupReader{formats: a.formats},
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
	success, ok := result.(*UpdateGroupOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateGroup: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
