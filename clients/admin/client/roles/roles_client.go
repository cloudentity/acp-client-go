// Code generated by go-swagger; DO NOT EDIT.

package roles

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new roles API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new roles API client with basic auth credentials.
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

// New creates a new roles API client with a bearer token for authentication.
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
Client for roles API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GrantIdentityPoolRole(params *GrantIdentityPoolRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantIdentityPoolRoleNoContent, error)

	GrantTenantRole(params *GrantTenantRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantTenantRoleNoContent, error)

	GrantWorkspaceRole(params *GrantWorkspaceRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantWorkspaceRoleNoContent, error)

	ListIdentityPoolRoles(params *ListIdentityPoolRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityPoolRolesOK, error)

	ListTenantRoles(params *ListTenantRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListTenantRolesOK, error)

	ListUserRoles(params *ListUserRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserRolesOK, error)

	ListWorkspaceRoles(params *ListWorkspaceRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListWorkspaceRolesOK, error)

	RevokeIdentityPoolRole(params *RevokeIdentityPoolRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeIdentityPoolRoleNoContent, error)

	RevokeTenantRole(params *RevokeTenantRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeTenantRoleNoContent, error)

	RevokeWorkspaceRole(params *RevokeWorkspaceRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeWorkspaceRoleNoContent, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GrantIdentityPoolRole grants identity pool role

Grant identityPool role.
*/
func (a *Client) GrantIdentityPoolRole(params *GrantIdentityPoolRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantIdentityPoolRoleNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGrantIdentityPoolRoleParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "grantIdentityPoolRole",
		Method:             "POST",
		PathPattern:        "/pools/{ipID}/roles/grant",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GrantIdentityPoolRoleReader{formats: a.formats},
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
	success, ok := result.(*GrantIdentityPoolRoleNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for grantIdentityPoolRole: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GrantTenantRole grants tenant role

Grant tenant role.
*/
func (a *Client) GrantTenantRole(params *GrantTenantRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantTenantRoleNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGrantTenantRoleParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "grantTenantRole",
		Method:             "POST",
		PathPattern:        "/tenant/roles/grant",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GrantTenantRoleReader{formats: a.formats},
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
	success, ok := result.(*GrantTenantRoleNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for grantTenantRole: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GrantWorkspaceRole grants workspace role

Grant workspace role.
*/
func (a *Client) GrantWorkspaceRole(params *GrantWorkspaceRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantWorkspaceRoleNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGrantWorkspaceRoleParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "grantWorkspaceRole",
		Method:             "POST",
		PathPattern:        "/servers/{wid}/roles/grant",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GrantWorkspaceRoleReader{formats: a.formats},
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
	success, ok := result.(*GrantWorkspaceRoleNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for grantWorkspaceRole: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListIdentityPoolRoles lists identity pool roles

List identityPool roles.
*/
func (a *Client) ListIdentityPoolRoles(params *ListIdentityPoolRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityPoolRolesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentityPoolRolesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentityPoolRoles",
		Method:             "GET",
		PathPattern:        "/pools/{ipID}/roles",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentityPoolRolesReader{formats: a.formats},
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
	success, ok := result.(*ListIdentityPoolRolesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentityPoolRoles: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListTenantRoles lists tenant roles

List tenant roles.
*/
func (a *Client) ListTenantRoles(params *ListTenantRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListTenantRolesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListTenantRolesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listTenantRoles",
		Method:             "GET",
		PathPattern:        "/tenant/roles",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListTenantRolesReader{formats: a.formats},
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
	success, ok := result.(*ListTenantRolesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listTenantRoles: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListUserRoles lists user roles

List user roles.
*/
func (a *Client) ListUserRoles(params *ListUserRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserRolesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUserRolesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUserRoles",
		Method:             "GET",
		PathPattern:        "/pools/{ipID}/users/{userID}/roles",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUserRolesReader{formats: a.formats},
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
	success, ok := result.(*ListUserRolesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUserRoles: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListWorkspaceRoles lists workspace roles

List workspace roles.
*/
func (a *Client) ListWorkspaceRoles(params *ListWorkspaceRolesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListWorkspaceRolesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListWorkspaceRolesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listWorkspaceRoles",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/roles",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListWorkspaceRolesReader{formats: a.formats},
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
	success, ok := result.(*ListWorkspaceRolesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listWorkspaceRoles: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RevokeIdentityPoolRole revokes identity pool role

Revoke identityPool role.
*/
func (a *Client) RevokeIdentityPoolRole(params *RevokeIdentityPoolRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeIdentityPoolRoleNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeIdentityPoolRoleParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeIdentityPoolRole",
		Method:             "DELETE",
		PathPattern:        "/pools/{ipID}/roles/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeIdentityPoolRoleReader{formats: a.formats},
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
	success, ok := result.(*RevokeIdentityPoolRoleNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeIdentityPoolRole: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RevokeTenantRole revokes tenant role

Revoke tenant role.
*/
func (a *Client) RevokeTenantRole(params *RevokeTenantRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeTenantRoleNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeTenantRoleParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeTenantRole",
		Method:             "DELETE",
		PathPattern:        "/tenant/roles/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeTenantRoleReader{formats: a.formats},
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
	success, ok := result.(*RevokeTenantRoleNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeTenantRole: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RevokeWorkspaceRole revokes workspace role

Revoke workspace role.
*/
func (a *Client) RevokeWorkspaceRole(params *RevokeWorkspaceRoleParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeWorkspaceRoleNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeWorkspaceRoleParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeWorkspaceRole",
		Method:             "DELETE",
		PathPattern:        "/servers/{wid}/roles/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeWorkspaceRoleReader{formats: a.formats},
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
	success, ok := result.(*RevokeWorkspaceRoleNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeWorkspaceRole: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
