// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new users API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new users API client with basic auth credentials.
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

// New creates a new users API client with a bearer token for authentication.
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
Client for users API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	AddUserIdentifier(params *AddUserIdentifierParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AddUserIdentifierOK, error)

	AddUserVerifiableAddress(params *AddUserVerifiableAddressParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AddUserVerifiableAddressOK, error)

	CreateUser(params *CreateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateUserCreated, error)

	DeleteUser(params *DeleteUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUserNoContent, error)

	DeleteUserIdentifier(params *DeleteUserIdentifierParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUserIdentifierNoContent, error)

	DeleteUserVerifiableAddress(params *DeleteUserVerifiableAddressParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUserVerifiableAddressNoContent, error)

	GetUser(params *GetUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserOK, error)

	GetUserMetadata(params *GetUserMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserMetadataOK, error)

	ListUsers(params *ListUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUsersOK, error)

	RequestResetPassword(params *RequestResetPasswordParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestResetPasswordNoContent, error)

	SendActivationMessage(params *SendActivationMessageParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SendActivationMessageNoContent, error)

	SetPasswordState(params *SetPasswordStateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetPasswordStateNoContent, error)

	SetUserMetadata(params *SetUserMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetUserMetadataOK, error)

	UpdateUser(params *UpdateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserOK, error)

	UpdateUserVerifiableAddress(params *UpdateUserVerifiableAddressParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserVerifiableAddressOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
AddUserIdentifier adds identifier

Add a new identifier to a user's profile in the specified identity pool.
*/
func (a *Client) AddUserIdentifier(params *AddUserIdentifierParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AddUserIdentifierOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAddUserIdentifierParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "addUserIdentifier",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/identifiers/add",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AddUserIdentifierReader{formats: a.formats},
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
	success, ok := result.(*AddUserIdentifierOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for addUserIdentifier: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
AddUserVerifiableAddress adds verifiable address

Add a verifiable address to the user account in the specified identity pool.
*/
func (a *Client) AddUserVerifiableAddress(params *AddUserVerifiableAddressParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AddUserVerifiableAddressOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAddUserVerifiableAddressParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "addUserVerifiableAddress",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/addresses/add",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AddUserVerifiableAddressReader{formats: a.formats},
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
	success, ok := result.(*AddUserVerifiableAddressOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for addUserVerifiableAddress: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	CreateUser creates user account

	Create a user with extended data.

Any status and set of identifiers, addresses, and credentials are allowed.
If credential of type password is provided it can be marked as must_be_changed which forces user to change its password upon first login.

When no `payload_schema_id` or `metadata_schema_id` are provided, the default values are taken from the
specified Identity Pool.

Payload and metadata must match the specified schema.

The response contains an extended view on user entry.

To retrieve a user entry without user creation, call the **Get User Details** endpoint.
*/
func (a *Client) CreateUser(params *CreateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateUserCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createUser",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateUserReader{formats: a.formats},
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
	success, ok := result.(*CreateUserCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteUser deletes user account

Remove a record about a user account in the specified identity pool.
*/
func (a *Client) DeleteUser(params *DeleteUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUserNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteUser",
		Method:             "DELETE",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteUserReader{formats: a.formats},
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
	success, ok := result.(*DeleteUserNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteUserIdentifier removes identifier

Remove an identifier from the specified user account.
*/
func (a *Client) DeleteUserIdentifier(params *DeleteUserIdentifierParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUserIdentifierNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteUserIdentifierParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteUserIdentifier",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/identifiers/remove",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteUserIdentifierReader{formats: a.formats},
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
	success, ok := result.(*DeleteUserIdentifierNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteUserIdentifier: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteUserVerifiableAddress deletes verifiable address

Remove a verifiable address from a user account so it is no longer associated with the specified user.
*/
func (a *Client) DeleteUserVerifiableAddress(params *DeleteUserVerifiableAddressParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUserVerifiableAddressNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteUserVerifiableAddressParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteUserVerifiableAddress",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/addresses/remove",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteUserVerifiableAddressReader{formats: a.formats},
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
	success, ok := result.(*DeleteUserVerifiableAddressNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteUserVerifiableAddress: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetUser gets user details

	Retrieve an extended information about a user record.

The response contains user's basic details, payload, and metadata, as well as all their identifiers,
addresses, and blurred credentials.
*/
func (a *Client) GetUser(params *GetUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getUser",
		Method:             "GET",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUserReader{formats: a.formats},
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
	success, ok := result.(*GetUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetUserMetadata gets user metadata

Retrieve user metadata by metadata type.
*/
func (a *Client) GetUserMetadata(params *GetUserMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserMetadataOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUserMetadataParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getUserMetadata",
		Method:             "GET",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/metadata/{metadataType}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUserMetadataReader{formats: a.formats},
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
	success, ok := result.(*GetUserMetadataOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getUserMetadata: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListUsers lists users

	Retrieve the list of users from the specified identity pool.

Results are sorted by user ID. No other sorting is supported.
*/
func (a *Client) ListUsers(params *ListUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUsersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUsersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUsers",
		Method:             "GET",
		PathPattern:        "/admin/pools/{ipID}/users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUsersReader{formats: a.formats},
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
	success, ok := result.(*ListUsersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUsers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RequestResetPassword requests password reset

	Send an OTP to reset a password.

The first step of the reset password flow. The `address` body parameter can be either `verified` or `unverified`.

A new OTP invalidates any previous OTPs sent for password reset.

Reset password OTP validity period is configured in the identity pool settings.
*/
func (a *Client) RequestResetPassword(params *RequestResetPasswordParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestResetPasswordNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRequestResetPasswordParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "requestResetPassword",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/password/reset/request",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RequestResetPasswordReader{formats: a.formats},
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
	success, ok := result.(*RequestResetPasswordNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for requestResetPassword: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	SendActivationMessage sends activation message

	Send an activation message to the user's provided address.

When no `address` is provided in the request body, the message is sent to the address saved for this user (if there
is only one address).

The request fails upon the following:

• `address` is not provided and user has no addresses or more than one.

• `address` is someone else's verified address or identifier.

• The user's `status` is not `new`.

This request invalidates any previously generated OTPs for user account activation.

When `code_type_in_message=link` or no value is provided for it, an activation link is generated.

Activation message validity period is configured in the identity pool settings.

❕ REFACTORED: `identifier` is renamed to `address` in the request body. For backward compatibility, the both
fields are available. If `identifier` is not empty, it overrides the `address` value.
*/
func (a *Client) SendActivationMessage(params *SendActivationMessageParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SendActivationMessageNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSendActivationMessageParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "sendActivationMessage",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/activation/send",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SendActivationMessageReader{formats: a.formats},
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
	success, ok := result.(*SendActivationMessageNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for sendActivationMessage: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	SetPasswordState sets password state

	There is a set of well-defined states password can be in:

`valid` - password is valid and can be used for authentication etc.
`must_be_reset` - password is not valid for authentication and must be reset
`must_be_changed` - password is valid for one authentication and then must be changed or will be moved to `must_be_reset` state
*/
func (a *Client) SetPasswordState(params *SetPasswordStateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetPasswordStateNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetPasswordStateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setPasswordState",
		Method:             "PUT",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/password/state",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetPasswordStateReader{formats: a.formats},
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
	success, ok := result.(*SetPasswordStateNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setPasswordState: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SetUserMetadata sets user metadata

Set user metadata for given metadata type.
*/
func (a *Client) SetUserMetadata(params *SetUserMetadataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetUserMetadataOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetUserMetadataParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setUserMetadata",
		Method:             "PUT",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/metadata/{metadataType}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetUserMetadataReader{formats: a.formats},
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
	success, ok := result.(*SetUserMetadataOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setUserMetadata: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	UpdateUser updates user record

	Update the basic set of user data: payload, metadata, schemas, and status. Provide the required values for the fields

you need to update. Fields (top level elements like `status`, `payload` etc.) with no values are skipped for the update (not removed nor cleared).

The fields to be updated are overridden.

Any `payload` / `metadata` and `payload_schema_id` / `metadata_schema_id` values passed must be mutually relevant.

To retrieve a user entry without updating their record, call the **Get User Details** endpoint.

Please notice that `deleted` status may be used as soft-delete but does not have any special meaning in the
system besides it does not allow such user to authenticate.
*/
func (a *Client) UpdateUser(params *UpdateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateUser",
		Method:             "PUT",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateUserReader{formats: a.formats},
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
	success, ok := result.(*UpdateUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateUserVerifiableAddress updates verifiable address

Updates a verifiable address for the user account.
*/
func (a *Client) UpdateUserVerifiableAddress(params *UpdateUserVerifiableAddressParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserVerifiableAddressOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateUserVerifiableAddressParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateUserVerifiableAddress",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/addresses/update",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateUserVerifiableAddressReader{formats: a.formats},
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
	success, ok := result.(*UpdateUserVerifiableAddressOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateUserVerifiableAddress: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
