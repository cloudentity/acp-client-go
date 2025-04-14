// Code generated by go-swagger; DO NOT EDIT.

package oauth2

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new oauth2 API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for oauth2 API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	Authorize(params *AuthorizeParams, opts ...ClientOption) error

	BackchannelAuthentication(params *BackchannelAuthenticationParams, opts ...ClientOption) (*BackchannelAuthenticationOK, error)

	DeviceAuthorization(params *DeviceAuthorizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeviceAuthorizationOK, error)

	DynamicClientRegistration(params *DynamicClientRegistrationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationCreated, error)

	DynamicClientRegistrationDeleteClient(params *DynamicClientRegistrationDeleteClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationDeleteClientNoContent, error)

	DynamicClientRegistrationGetClient(params *DynamicClientRegistrationGetClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationGetClientOK, error)

	DynamicClientRegistrationUpdateClient(params *DynamicClientRegistrationUpdateClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationUpdateClientOK, error)

	Introspect(params *IntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*IntrospectOK, error)

	Jwks(params *JwksParams, opts ...ClientOption) (*JwksOK, error)

	PushedAuthorizationRequest(params *PushedAuthorizationRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PushedAuthorizationRequestCreated, error)

	Revoke(params *RevokeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeOK, error)

	RpInitiatedLogout(params *RpInitiatedLogoutParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RpInitiatedLogoutOK, error)

	RpInitiatedLogoutPost(params *RpInitiatedLogoutPostParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RpInitiatedLogoutPostOK, error)

	Token(params *TokenParams, opts ...ClientOption) (*TokenOK, error)

	Userinfo(params *UserinfoParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UserinfoOK, error)

	WellKnown(params *WellKnownParams, opts ...ClientOption) (*WellKnownOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	Authorize thes o auth 2 0 authorize endpoint

	The authorization endpoint is used to interact with the resource

owner and obtain an authorization grant.
*/
func (a *Client) Authorize(params *AuthorizeParams, opts ...ClientOption) error {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAuthorizeParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "authorize",
		Method:             "GET",
		PathPattern:        "/oauth2/authorize",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AuthorizeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	_, err := a.transport.Submit(op)
	if err != nil {
		return err
	}
	return nil
}

/*
BackchannelAuthentication opens ID connect client initiated backchannel authentication endpoint

Client-Initiated Backchannel Authentication defines an authentication request that is requested directly from the Client to the OpenID Provider without going through the user's browser.
*/
func (a *Client) BackchannelAuthentication(params *BackchannelAuthenticationParams, opts ...ClientOption) (*BackchannelAuthenticationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewBackchannelAuthenticationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "backchannelAuthentication",
		Method:             "POST",
		PathPattern:        "/backchannel/authentication",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &BackchannelAuthenticationReader{formats: a.formats},
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
	success, ok := result.(*BackchannelAuthenticationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for backchannelAuthentication: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	DeviceAuthorization os auth 2 0 device authorization endpoint

	The Device Authorization endpoint is designed for Internet-

connected devices that either lack a browser to perform a user-agent-
based authorization or are input constrained to the extent that
requiring the user to input text in order to authenticate during the
authorization flow is impractical.
*/
func (a *Client) DeviceAuthorization(params *DeviceAuthorizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeviceAuthorizationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeviceAuthorizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deviceAuthorization",
		Method:             "POST",
		PathPattern:        "/device/authorization",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeviceAuthorizationReader{formats: a.formats},
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
	success, ok := result.(*DeviceAuthorizationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deviceAuthorization: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	DynamicClientRegistration os auth 2 0 dynamic client registration endpoint

	Dynamic Client Registration endpoint allows to dynamically register OAuth 2.0 client applications

with the Cloudentity Platform. When a request with all required registration metadata
values reaches the Cloudentity authorization server, the server issues a client
identifier and provides client metadata values registered for the client.
Client applications can use their registration data to communicate with the Cloudentity
platform using the OAuth 2.0 protocol.
*/
func (a *Client) DynamicClientRegistration(params *DynamicClientRegistrationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDynamicClientRegistrationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "dynamicClientRegistration",
		Method:             "POST",
		PathPattern:        "/oauth2/register",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DynamicClientRegistrationReader{formats: a.formats},
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
	success, ok := result.(*DynamicClientRegistrationCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for dynamicClientRegistration: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DynamicClientRegistrationDeleteClient os auth 2 0 dynamic client registration delete client endpoint

This endpoint allows to delete a dynamically registered client.
*/
func (a *Client) DynamicClientRegistrationDeleteClient(params *DynamicClientRegistrationDeleteClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationDeleteClientNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDynamicClientRegistrationDeleteClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "dynamicClientRegistrationDeleteClient",
		Method:             "DELETE",
		PathPattern:        "/oauth2/register/{cid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DynamicClientRegistrationDeleteClientReader{formats: a.formats},
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
	success, ok := result.(*DynamicClientRegistrationDeleteClientNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for dynamicClientRegistrationDeleteClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DynamicClientRegistrationGetClient os auth 2 0 dynamic client registration get client endpoint

This endpoint allows to get metadata values of a dynamically registered client.
*/
func (a *Client) DynamicClientRegistrationGetClient(params *DynamicClientRegistrationGetClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationGetClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDynamicClientRegistrationGetClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "dynamicClientRegistrationGetClient",
		Method:             "GET",
		PathPattern:        "/oauth2/register/{cid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DynamicClientRegistrationGetClientReader{formats: a.formats},
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
	success, ok := result.(*DynamicClientRegistrationGetClientOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for dynamicClientRegistrationGetClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DynamicClientRegistrationUpdateClient os auth 2 0 dynamic client registration update client endpoint

This endpoint allows to update metadata values of a dynamically registered client.
*/
func (a *Client) DynamicClientRegistrationUpdateClient(params *DynamicClientRegistrationUpdateClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DynamicClientRegistrationUpdateClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDynamicClientRegistrationUpdateClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "dynamicClientRegistrationUpdateClient",
		Method:             "PUT",
		PathPattern:        "/oauth2/register/{cid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DynamicClientRegistrationUpdateClientReader{formats: a.formats},
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
	success, ok := result.(*DynamicClientRegistrationUpdateClientOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for dynamicClientRegistrationUpdateClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	Introspect thes o auth 2 0 introspection endpoint

	Takes the `token` parameter representing an OAuth 2.0 token (the one the application wants to

introspect) and returns a JSON
representing the metadata surrounding the token such as, for example,
whether the token is still active, what are the approved access scopes, what is the
authentication context in which the token was issued.

Token introspection allows resource servers or applications to
query this information regardless of whether or not it is carried in
the token itself. It allows to use this method along with or
independently of structured token values.  Additionally, you can use the mechanism to
introspect the token in a particular authentication context
and ascertain the relevant metadata about the token to make the
authorization decision appropriately.

Client applications that call the OAuth 2.0 Introspection Endpoint must authenticate with the
Cloudentity authorization server either with a valid access token provided as the value of
the `Authorization: Bearer $AT` request header or using the client authentication method
configured for the client application.

When a client application is assigned the `introspect_tokens` scope, it can introspect tokens
that belong to client applications **registered within the same workspace** as the client app
requesting the token instrospection. When a client application has no `introspect_tokens` scope
assigned, it can **only introspect its tokens**.
*/
func (a *Client) Introspect(params *IntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*IntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewIntrospectParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "introspect",
		Method:             "POST",
		PathPattern:        "/oauth2/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &IntrospectReader{formats: a.formats},
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
	success, ok := result.(*IntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for introspect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	Jwks JSONs web keys discovery endpoint

	This endpoint returns the signing key(s) the client uses to validate

signatures from the authorization server.
*/
func (a *Client) Jwks(params *JwksParams, opts ...ClientOption) (*JwksOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewJwksParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "jwks",
		Method:             "GET",
		PathPattern:        "/.well-known/jwks.json",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &JwksReader{formats: a.formats},
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
	success, ok := result.(*JwksOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for jwks: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	PushedAuthorizationRequest pusheds authorization request p a r endpoint

	This endpoint allows clients to push the payload of an OAuth 2.0 authorization request to the authorization server

via a direct request and provides them with a request URI that is used as reference to the data in a subsequent call
to the authorization endpoint.
*/
func (a *Client) PushedAuthorizationRequest(params *PushedAuthorizationRequestParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PushedAuthorizationRequestCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPushedAuthorizationRequestParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "pushedAuthorizationRequest",
		Method:             "POST",
		PathPattern:        "/par",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PushedAuthorizationRequestReader{formats: a.formats},
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
	success, ok := result.(*PushedAuthorizationRequestCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for pushedAuthorizationRequest: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	Revoke thes o auth 2 0 revocation endpoint

	Supports revocation of access and refresh tokens. The token to be revoked must be provided as the

value of the `token` parameter. When a token is revoked, it cannot be used to, for example,
exchange a refresh token to an access token.

Client applications that call the OAuth 2.0 Revocation Endpoint must authenticate with the
Cloudentity authorization server either
with a valid access token provided as the value of the `Authorization: Bearer $AT` request header
or using the client authentication method configured for the client application.

When a client application is assigned the `revoke_tokens` scope, it can revoke tokens
that belong to client applications **registered within the same workspace** as the client app
requesting the token revocation. When a client application has no `revoke_tokens` scope
assigned, it can **only revoke its tokens**.
*/
func (a *Client) Revoke(params *RevokeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revoke",
		Method:             "POST",
		PathPattern:        "/oauth2/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeReader{formats: a.formats},
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
	success, ok := result.(*RevokeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revoke: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RpInitiatedLogout os ID c 1 0 r p initiated logout endpoint

	Perform RP-Initiated Logout. See

[OpenID Connect RP-Initiated Logout 1.0 spec](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
*/
func (a *Client) RpInitiatedLogout(params *RpInitiatedLogoutParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RpInitiatedLogoutOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRpInitiatedLogoutParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "rpInitiatedLogout",
		Method:             "GET",
		PathPattern:        "/oidc/logout",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RpInitiatedLogoutReader{formats: a.formats},
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
	success, ok := result.(*RpInitiatedLogoutOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for rpInitiatedLogout: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RpInitiatedLogoutPost os ID c 1 0 r p initiated logout endpoint

	Perform RP-Initiated Logout. See

[OpenID Connect RP-Initiated Logout 1.0 spec](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
*/
func (a *Client) RpInitiatedLogoutPost(params *RpInitiatedLogoutPostParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RpInitiatedLogoutPostOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRpInitiatedLogoutPostParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "rpInitiatedLogoutPost",
		Method:             "POST",
		PathPattern:        "/oidc/logout",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RpInitiatedLogoutPostReader{formats: a.formats},
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
	success, ok := result.(*RpInitiatedLogoutPostOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for rpInitiatedLogoutPost: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	Token thes o auth 2 0 token endpoint

	The token endpoint is used by the client to obtain an access token by

presenting its authorization grant or refresh token.
*/
func (a *Client) Token(params *TokenParams, opts ...ClientOption) (*TokenOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewTokenParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "token",
		Method:             "POST",
		PathPattern:        "/oauth2/token",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &TokenReader{formats: a.formats},
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
	success, ok := result.(*TokenOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for token: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	Userinfo opens ID connect userinfo endpoint

	The UserInfo Endpoint is an OAuth 2.0 Protected Resource that

returns Claims about the authenticated End-User. To obtain the requested
Claims about the End-User, the Client makes a request to the UserInfo Endpoint
using an Access Token obtained through OpenID Connect Authentication. These Claims
are represented by a JSON object that contains a collection of name and value
pairs for the Claims.
*/
func (a *Client) Userinfo(params *UserinfoParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UserinfoOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUserinfoParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "userinfo",
		Method:             "GET",
		PathPattern:        "/userinfo",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UserinfoReader{formats: a.formats},
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
	success, ok := result.(*UserinfoOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for userinfo: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
WellKnown opens ID connect discovery endpoint

Returns OpenID configuration.
*/
func (a *Client) WellKnown(params *WellKnownParams, opts ...ClientOption) (*WellKnownOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewWellKnownParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "wellKnown",
		Method:             "GET",
		PathPattern:        "/.well-known/openid-configuration",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &WellKnownReader{formats: a.formats},
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
	success, ok := result.(*WellKnownOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for wellKnown: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
