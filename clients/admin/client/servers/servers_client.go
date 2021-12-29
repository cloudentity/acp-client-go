// Code generated by go-swagger; DO NOT EDIT.

package servers

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new servers API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for servers API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	BindServer(params *BindServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*BindServerOK, error)

	CreateAuthorizationServer(params *CreateAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateAuthorizationServerCreated, error)

	DeleteAuthorizationServer(params *DeleteAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteAuthorizationServerNoContent, error)

	GetAuthorizationServer(params *GetAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAuthorizationServerOK, error)

	GetCIBAAuthenticationService(params *GetCIBAAuthenticationServiceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetCIBAAuthenticationServiceOK, error)

	GetServerConsent(params *GetServerConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetServerConsentOK, error)

	ListAuthorizationServers(params *ListAuthorizationServersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListAuthorizationServersOK, error)

	ListDashboards(params *ListDashboardsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListDashboardsOK, error)

	ListServersBindings(params *ListServersBindingsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListServersBindingsOK, error)

	SetCIBAAuthenticationService(params *SetCIBAAuthenticationServiceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetCIBAAuthenticationServiceOK, error)

	SetServerConsent(params *SetServerConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetServerConsentOK, error)

	UnbindServer(params *UnbindServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UnbindServerOK, error)

	UpdateAuthorizationServer(params *UpdateAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateAuthorizationServerOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  BindServer binds server

  Bind server.
*/
func (a *Client) BindServer(params *BindServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*BindServerOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewBindServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "bindServer",
		Method:             "POST",
		PathPattern:        "/servers/{wid}/bind/{rid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &BindServerReader{formats: a.formats},
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
	success, ok := result.(*BindServerOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for bindServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  CreateAuthorizationServer creates authorization server

  Multiple authorization servers with unique id can be created within a tenant.
If id and secret are not provided, will be generated.
Secret if provided must have at least 32 characters.

You can set what grant types will be supported by authorization server. The defaults are:
`{"grant_types": ["authorization_code", "implicit", "client_credentials", "refresh_token"]}`

If jwks keys are not provided explicitly, will be generated based on provided `key_type` algorithm (rsa by default).

TTLs for tokens and authorization code can be customized. The defaults are:

`authorization_code_ttl` - 10 minutes
`access_token_ttl` - 1 hour
`id_token_ttl` - 1 hour
`refresh_token_ttl` - 30 days

If you want to enable dynamic client registration set `{"enable_dynamic_client_registration": true}`.

If you want to create FAPI read write compliant server set: `{"profiles"": ["fapi_rw"]}`.

If you want to enforce PKCE set `{"enforce_pkce": true}`.
*/
func (a *Client) CreateAuthorizationServer(params *CreateAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateAuthorizationServerCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateAuthorizationServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createAuthorizationServer",
		Method:             "POST",
		PathPattern:        "/servers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateAuthorizationServerReader{formats: a.formats},
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
	success, ok := result.(*CreateAuthorizationServerCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createAuthorizationServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteAuthorizationServer deletes authorization server

  Delete authorization server.
*/
func (a *Client) DeleteAuthorizationServer(params *DeleteAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteAuthorizationServerNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteAuthorizationServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteAuthorizationServer",
		Method:             "DELETE",
		PathPattern:        "/servers/{wid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteAuthorizationServerReader{formats: a.formats},
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
	success, ok := result.(*DeleteAuthorizationServerNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteAuthorizationServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAuthorizationServer gets authorization server

  Get authorization server.
*/
func (a *Client) GetAuthorizationServer(params *GetAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAuthorizationServerOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAuthorizationServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getAuthorizationServer",
		Method:             "GET",
		PathPattern:        "/servers/{wid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAuthorizationServerReader{formats: a.formats},
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
	success, ok := result.(*GetAuthorizationServerOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getAuthorizationServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetCIBAAuthenticationService gets c i b a authentication service

  This API returns details of CIBA authentication service.
*/
func (a *Client) GetCIBAAuthenticationService(params *GetCIBAAuthenticationServiceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetCIBAAuthenticationServiceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetCIBAAuthenticationServiceParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getCIBAAuthenticationService",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/ciba-authentication-service",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetCIBAAuthenticationServiceReader{formats: a.formats},
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
	success, ok := result.(*GetCIBAAuthenticationServiceOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getCIBAAuthenticationService: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetServerConsent gets server consent

  Get server consent.
*/
func (a *Client) GetServerConsent(params *GetServerConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetServerConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetServerConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getServerConsent",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/server-consent",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetServerConsentReader{formats: a.formats},
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
	success, ok := result.(*GetServerConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getServerConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListAuthorizationServers lists authorization servers

  List authorization servers.
*/
func (a *Client) ListAuthorizationServers(params *ListAuthorizationServersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListAuthorizationServersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListAuthorizationServersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listAuthorizationServers",
		Method:             "GET",
		PathPattern:        "/servers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListAuthorizationServersReader{formats: a.formats},
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
	success, ok := result.(*ListAuthorizationServersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listAuthorizationServers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListDashboards lists links to dashboards

  List links to dashboards.
*/
func (a *Client) ListDashboards(params *ListDashboardsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListDashboardsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListDashboardsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listDashboards",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/dashboards",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListDashboardsReader{formats: a.formats},
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
	success, ok := result.(*ListDashboardsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listDashboards: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListServersBindings lists servers bindings

  List servers bindings.
*/
func (a *Client) ListServersBindings(params *ListServersBindingsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListServersBindingsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListServersBindingsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listServersBindings",
		Method:             "GET",
		PathPattern:        "/servers-bindings",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListServersBindingsReader{formats: a.formats},
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
	success, ok := result.(*ListServersBindingsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listServersBindings: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  SetCIBAAuthenticationService sets c i b a authentication service

  If you want to enable CIBA for the workspace, you need to provide url to external service that implements
rest api specified by ACP.
*/
func (a *Client) SetCIBAAuthenticationService(params *SetCIBAAuthenticationServiceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetCIBAAuthenticationServiceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetCIBAAuthenticationServiceParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setCIBAAuthenticationService",
		Method:             "PUT",
		PathPattern:        "/servers/{wid}/ciba-authentication-service",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetCIBAAuthenticationServiceReader{formats: a.formats},
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
	success, ok := result.(*SetCIBAAuthenticationServiceOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setCIBAAuthenticationService: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  SetServerConsent sets server consent

  Set server consent. For custom server consent a client in system server is created automatically.
*/
func (a *Client) SetServerConsent(params *SetServerConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetServerConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetServerConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setServerConsent",
		Method:             "PUT",
		PathPattern:        "/servers/{wid}/server-consent",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetServerConsentReader{formats: a.formats},
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
	success, ok := result.(*SetServerConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setServerConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UnbindServer unbinds server

  Unbind server.
*/
func (a *Client) UnbindServer(params *UnbindServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UnbindServerOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUnbindServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "unbindServer",
		Method:             "DELETE",
		PathPattern:        "/servers/{wid}/unbind/{rid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UnbindServerReader{formats: a.formats},
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
	success, ok := result.(*UnbindServerOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for unbindServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateAuthorizationServer updates authorization server

  Update authorization server.
*/
func (a *Client) UpdateAuthorizationServer(params *UpdateAuthorizationServerParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateAuthorizationServerOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateAuthorizationServerParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateAuthorizationServer",
		Method:             "PUT",
		PathPattern:        "/servers/{wid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateAuthorizationServerReader{formats: a.formats},
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
	success, ok := result.(*UpdateAuthorizationServerOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateAuthorizationServer: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
