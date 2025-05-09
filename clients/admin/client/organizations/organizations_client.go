// Code generated by go-swagger; DO NOT EDIT.

package organizations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new organizations API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new organizations API client with basic auth credentials.
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

// New creates a new organizations API client with a bearer token for authentication.
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
Client for organizations API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateOrganization(params *CreateOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateOrganizationCreated, error)

	DeleteOrganization(params *DeleteOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteOrganizationNoContent, error)

	GetOrganization(params *GetOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetOrganizationOK, error)

	ListOrganizations(params *ListOrganizationsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListOrganizationsOK, error)

	ListUserOrganizations(params *ListUserOrganizationsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserOrganizationsOK, error)

	UpdateOrganization(params *UpdateOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateOrganizationOK, error)

	UpdateOrganizationMetadata(params *UpdateOrganizationMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateOrganizationMetadataOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateOrganization creates organization
*/
func (a *Client) CreateOrganization(params *CreateOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateOrganizationCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateOrganizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createOrganization",
		Method:             "POST",
		PathPattern:        "/organizations",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateOrganizationReader{formats: a.formats},
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
	success, ok := result.(*CreateOrganizationCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createOrganization: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteOrganization deletes organization

Delete organization.
*/
func (a *Client) DeleteOrganization(params *DeleteOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteOrganizationNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteOrganizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteOrganization",
		Method:             "DELETE",
		PathPattern:        "/organizations/{wid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteOrganizationReader{formats: a.formats},
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
	success, ok := result.(*DeleteOrganizationNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteOrganization: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetOrganization gets organization

Get organization.
*/
func (a *Client) GetOrganization(params *GetOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetOrganizationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetOrganizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getOrganization",
		Method:             "GET",
		PathPattern:        "/organizations/{wid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetOrganizationReader{formats: a.formats},
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
	success, ok := result.(*GetOrganizationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getOrganization: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListOrganizations lists organizations

List organizations.
*/
func (a *Client) ListOrganizations(params *ListOrganizationsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListOrganizationsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListOrganizationsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listOrganizations",
		Method:             "GET",
		PathPattern:        "/organizations",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListOrganizationsReader{formats: a.formats},
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
	success, ok := result.(*ListOrganizationsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listOrganizations: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListUserOrganizations lists user organizations

List organizations that the current user has access to.
*/
func (a *Client) ListUserOrganizations(params *ListUserOrganizationsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserOrganizationsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUserOrganizationsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUserOrganizations",
		Method:             "GET",
		PathPattern:        "/user/organizations",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUserOrganizationsReader{formats: a.formats},
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
	success, ok := result.(*ListUserOrganizationsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUserOrganizations: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateOrganization updates organization

Update organization.
*/
func (a *Client) UpdateOrganization(params *UpdateOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateOrganizationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateOrganizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateOrganization",
		Method:             "PUT",
		PathPattern:        "/organizations/{wid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateOrganizationReader{formats: a.formats},
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
	success, ok := result.(*UpdateOrganizationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateOrganization: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateOrganizationMetadata updates organization metadata

Update organization metadata.
*/
func (a *Client) UpdateOrganizationMetadata(params *UpdateOrganizationMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateOrganizationMetadataOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateOrganizationMetadataParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateOrganizationMetadata",
		Method:             "PUT",
		PathPattern:        "/organizations/{wid}/metadata",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateOrganizationMetadataReader{formats: a.formats},
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
	success, ok := result.(*UpdateOrganizationMetadataOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateOrganizationMetadata: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
