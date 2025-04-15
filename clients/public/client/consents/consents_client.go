// Code generated by go-swagger; DO NOT EDIT.

package consents

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new consents API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new consents API client with basic auth credentials.
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

// New creates a new consents API client with a bearer token for authentication.
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
Client for consents API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GrantConsent(params *GrantConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantConsentCreated, error)

	ListPrivacyLedgerEvents(params *ListPrivacyLedgerEventsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListPrivacyLedgerEventsOK, error)

	ListUserConsents(params *ListUserConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserConsentsOK, error)

	ListUserConsentsByAction(params *ListUserConsentsByActionParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserConsentsByActionOK, error)

	PatchConsentGrants(params *PatchConsentGrantsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PatchConsentGrantsCreated, error)

	RevokeConsent(params *RevokeConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeConsentOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	GrantConsent grants privacy consent

	Consent id must be provided in the request body.

When a user grants consent which was already granted, it does not result in an error but it silently skipped instead.
*/
func (a *Client) GrantConsent(params *GrantConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GrantConsentCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGrantConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "grantConsent",
		Method:             "POST",
		PathPattern:        "/privacy/consents/grant",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GrantConsentReader{formats: a.formats},
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
	success, ok := result.(*GrantConsentCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for grantConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListPrivacyLedgerEvents lists privacy ledger events

It is possible to provide time constraints using from and to query params.
*/
func (a *Client) ListPrivacyLedgerEvents(params *ListPrivacyLedgerEventsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListPrivacyLedgerEventsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListPrivacyLedgerEventsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listPrivacyLedgerEvents",
		Method:             "GET",
		PathPattern:        "/privacy/events",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListPrivacyLedgerEventsReader{formats: a.formats},
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
	success, ok := result.(*ListPrivacyLedgerEventsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listPrivacyLedgerEvents: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListUserConsents lists consents

If you want to list only specific consents, provide consent identifiers in query params.
*/
func (a *Client) ListUserConsents(params *ListUserConsentsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserConsentsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUserConsentsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUserConsents",
		Method:             "GET",
		PathPattern:        "/privacy/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUserConsentsReader{formats: a.formats},
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
	success, ok := result.(*ListUserConsentsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUserConsents: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ListUserConsentsByAction lists consents by action

	Returns any possible required consents that the app should ask the User about.

The response includes a list of consents (including the ones user already agreed to).
Inclusion of the consents which the user already agreed to can be used to inform the user what he already agreed to.
*/
func (a *Client) ListUserConsentsByAction(params *ListUserConsentsByActionParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListUserConsentsByActionOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListUserConsentsByActionParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listUserConsentsByAction",
		Method:             "GET",
		PathPattern:        "/privacy/consents/{action}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListUserConsentsByActionReader{formats: a.formats},
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
	success, ok := result.(*ListUserConsentsByActionOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listUserConsentsByAction: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	PatchConsentGrants patches consent grants

	This is a non-standardized PATCH request.

Allows to update multiple consents approval in one API call.

See ConsentGrantPatchRequest object for more information.
*/
func (a *Client) PatchConsentGrants(params *PatchConsentGrantsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PatchConsentGrantsCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchConsentGrantsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "patchConsentGrants",
		Method:             "PATCH",
		PathPattern:        "/privacy/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PatchConsentGrantsReader{formats: a.formats},
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
	success, ok := result.(*PatchConsentGrantsCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for patchConsentGrants: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RevokeConsent revokes privacy consent

	This API can be used to withdraw a consent which user previously gave.

Consent id must be provided in the request body.

When consent has the can_be_withdrawn flag set to false the API fails with an error saying that the consent cannot be revoked.
This flag is useful for scenarios in which the application cannot function without the consent from a User.
*/
func (a *Client) RevokeConsent(params *RevokeConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeConsent",
		Method:             "POST",
		PathPattern:        "/privacy/consents/revoke",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeConsentReader{formats: a.formats},
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
	success, ok := result.(*RevokeConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
