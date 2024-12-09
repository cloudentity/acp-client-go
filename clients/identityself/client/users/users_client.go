// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new users API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for users API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	BeginWebAuthnCredentialsGeneration(params *BeginWebAuthnCredentialsGenerationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*BeginWebAuthnCredentialsGenerationOK, error)

	ChangePassword(params *ChangePasswordParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ChangePasswordNoContent, error)

	ChangePasswordV2(params *ChangePasswordV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ChangePasswordV2NoContent, error)

	ChangeTotpSecret(params *ChangeTotpSecretParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ChangeTotpSecretNoContent, error)

	CompleteWebAuthnCredentialsGeneration(params *CompleteWebAuthnCredentialsGenerationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CompleteWebAuthnCredentialsGenerationOK, error)

	DeleteWebAuthnKey(params *DeleteWebAuthnKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteWebAuthnKeyNoContent, error)

	GetUserProfile(params *GetUserProfileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserProfileOK, error)

	GetUserProfileV2(params *GetUserProfileV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserProfileV2OK, error)

	NameWebAuthnKey(params *NameWebAuthnKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*NameWebAuthnKeyNoContent, error)

	ResetPasswordConfirm(params *ResetPasswordConfirmParams, opts ...ClientOption) (*ResetPasswordConfirmNoContent, error)

	SetPassword(params *SetPasswordParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetPasswordNoContent, error)

	SetTotpSecret(params *SetTotpSecretParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetTotpSecretNoContent, error)

	SetWebAuthn(params *SetWebAuthnParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetWebAuthnNoContent, error)

	UpdateUserProfile(params *UpdateUserProfileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserProfileOK, error)

	UpdateUserProfileV2(params *UpdateUserProfileV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserProfileV2OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	BeginWebAuthnCredentialsGeneration begins web authn credentials generation

	Begin WebAuthn credentials generation

This API requires authentication to happen within the last 5 minutes.
*/
func (a *Client) BeginWebAuthnCredentialsGeneration(params *BeginWebAuthnCredentialsGenerationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*BeginWebAuthnCredentialsGenerationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewBeginWebAuthnCredentialsGenerationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "beginWebAuthnCredentialsGeneration",
		Method:             "POST",
		PathPattern:        "/v2/self/webauthn/create/begin",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &BeginWebAuthnCredentialsGenerationReader{formats: a.formats},
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
	success, ok := result.(*BeginWebAuthnCredentialsGenerationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for beginWebAuthnCredentialsGeneration: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ChangePassword changes password

Changes user password if provided password matches current user password.
*/
func (a *Client) ChangePassword(params *ChangePasswordParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ChangePasswordNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewChangePasswordParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "changePassword",
		Method:             "POST",
		PathPattern:        "/self/change-password",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ChangePasswordReader{formats: a.formats},
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
	success, ok := result.(*ChangePasswordNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for changePassword: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ChangePasswordV2 changes password

Changes user password if provided password matches current user password.
*/
func (a *Client) ChangePasswordV2(params *ChangePasswordV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ChangePasswordV2NoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewChangePasswordV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "changePasswordV2",
		Method:             "POST",
		PathPattern:        "/v2/self/change-password",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ChangePasswordV2Reader{formats: a.formats},
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
	success, ok := result.(*ChangePasswordV2NoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for changePasswordV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ChangeTotpSecret changes totp secret

Changes user totp secret if provided totp code is valid.
*/
func (a *Client) ChangeTotpSecret(params *ChangeTotpSecretParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ChangeTotpSecretNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewChangeTotpSecretParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "changeTotpSecret",
		Method:             "POST",
		PathPattern:        "/v2/self/change-totp-secret",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ChangeTotpSecretReader{formats: a.formats},
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
	success, ok := result.(*ChangeTotpSecretNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for changeTotpSecret: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	CompleteWebAuthnCredentialsGeneration finishes web authn credentials generation

	Finish WebAuthn credentials generation

This API requires authentication to happen within the last 5 minutes.
*/
func (a *Client) CompleteWebAuthnCredentialsGeneration(params *CompleteWebAuthnCredentialsGenerationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CompleteWebAuthnCredentialsGenerationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCompleteWebAuthnCredentialsGenerationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "completeWebAuthnCredentialsGeneration",
		Method:             "POST",
		PathPattern:        "/v2/self/webauthn/create/complete",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CompleteWebAuthnCredentialsGenerationReader{formats: a.formats},
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
	success, ok := result.(*CompleteWebAuthnCredentialsGenerationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for completeWebAuthnCredentialsGeneration: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	DeleteWebAuthnKey deletes web authn key

	Deletes WebAuthn key.

NOTICE: it is forbidden to delete the last WebAuthn key.
*/
func (a *Client) DeleteWebAuthnKey(params *DeleteWebAuthnKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteWebAuthnKeyNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteWebAuthnKeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteWebAuthnKey",
		Method:             "DELETE",
		PathPattern:        "/v2/self/webauthn/{webAuthnCredentialID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteWebAuthnKeyReader{formats: a.formats},
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
	success, ok := result.(*DeleteWebAuthnKeyNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteWebAuthnKey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetUserProfile selves get user profile

	Returns base view on user entry. Besides basic user entry it returns all user identifiers and addresses.

Also returns user metadata (only fields not marked as hidden) and payload.
*/
func (a *Client) GetUserProfile(params *GetUserProfileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserProfileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUserProfileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getUserProfile",
		Method:             "GET",
		PathPattern:        "/self/me",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUserProfileReader{formats: a.formats},
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
	success, ok := result.(*GetUserProfileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getUserProfile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	GetUserProfileV2 selves get user profile

	Returns base view on user entry. Besides basic user entry it returns all user identifiers and addresses.

Also returns user metadata (only fields not marked as hidden) and payload.
*/
func (a *Client) GetUserProfileV2(params *GetUserProfileV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserProfileV2OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUserProfileV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "getUserProfileV2",
		Method:             "GET",
		PathPattern:        "/v2/self/me",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUserProfileV2Reader{formats: a.formats},
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
	success, ok := result.(*GetUserProfileV2OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getUserProfileV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
NameWebAuthnKey names web authn key

Set name for WebAuthn key
*/
func (a *Client) NameWebAuthnKey(params *NameWebAuthnKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*NameWebAuthnKeyNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewNameWebAuthnKeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "nameWebAuthnKey",
		Method:             "PUT",
		PathPattern:        "/v2/self/webauthn/{webAuthnCredentialID}/name",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &NameWebAuthnKeyReader{formats: a.formats},
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
	success, ok := result.(*NameWebAuthnKeyNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for nameWebAuthnKey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ResetPasswordConfirm confirms reset password

	Resets password for user if the provided OTP is valid. It's the second and final step of the

flow to reset the password.
Either user identifier or extended code must be provided.
Endpoint returns generic `401` regardless of the reason of failure to prevent email/mobile enumeration.
After a successful password reset, OTP gets invalidated, so it cannot be reused.
Endpoint is protected by Brute Force mechanism.
*/
func (a *Client) ResetPasswordConfirm(params *ResetPasswordConfirmParams, opts ...ClientOption) (*ResetPasswordConfirmNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewResetPasswordConfirmParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "resetPasswordConfirm",
		Method:             "POST",
		PathPattern:        "/public/pools/{ipID}/reset-password/confirm",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ResetPasswordConfirmReader{formats: a.formats},
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
	success, ok := result.(*ResetPasswordConfirmNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for resetPasswordConfirm: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	SetPassword sets password

	Set a password for a user who doesn't have one yet

This API requires authentication to happen within the last 5 minutes.
*/
func (a *Client) SetPassword(params *SetPasswordParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetPasswordNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetPasswordParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setPassword",
		Method:             "POST",
		PathPattern:        "/v2/self/set-password",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetPasswordReader{formats: a.formats},
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
	success, ok := result.(*SetPasswordNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setPassword: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	SetTotpSecret sets totp secret

	Set totp secret for a user who doesn't have one yet

This API requires authentication to happen within the last 5 minutes.
*/
func (a *Client) SetTotpSecret(params *SetTotpSecretParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetTotpSecretNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetTotpSecretParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setTotpSecret",
		Method:             "POST",
		PathPattern:        "/v2/self/set-totp-secret",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetTotpSecretReader{formats: a.formats},
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
	success, ok := result.(*SetTotpSecretNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setTotpSecret: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	SetWebAuthn sets web authn

	Set WebAuthn for a user who doesn't have one yet

This API requires authentication to happen within the last 5 minutes.
*/
func (a *Client) SetWebAuthn(params *SetWebAuthnParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetWebAuthnNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetWebAuthnParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setWebAuthn",
		Method:             "POST",
		PathPattern:        "/v2/self/set-webauthn",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetWebAuthnReader{formats: a.formats},
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
	success, ok := result.(*SetWebAuthnNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setWebAuthn: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	UpdateUserProfile selves update user profile

	Updates user payload.

Payload must be valid against schema defined in user entry.

Returns base view on user entry (see Self Get User Profile endpoint).
*/
func (a *Client) UpdateUserProfile(params *UpdateUserProfileParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserProfileOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateUserProfileParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateUserProfile",
		Method:             "PUT",
		PathPattern:        "/self/me",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateUserProfileReader{formats: a.formats},
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
	success, ok := result.(*UpdateUserProfileOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateUserProfile: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	UpdateUserProfileV2 selves update user profile

	Updates user payload.

Payload must be valid against schema defined in user entry.

Returns base view on user entry (see Self Get User Profile endpoint).
*/
func (a *Client) UpdateUserProfileV2(params *UpdateUserProfileV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserProfileV2OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateUserProfileV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateUserProfileV2",
		Method:             "PUT",
		PathPattern:        "/v2/self/me",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateUserProfileV2Reader{formats: a.formats},
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
	success, ok := result.(*UpdateUserProfileV2OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateUserProfileV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
