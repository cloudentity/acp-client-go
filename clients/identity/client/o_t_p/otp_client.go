// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new o t p API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new o t p API client with basic auth credentials.
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

// New creates a new o t p API client with a bearer token for authentication.
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
Client for o t p API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	RequestAddressVerification(params *RequestAddressVerificationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestAddressVerificationNoContent, error)

	RequestOTPChallenge(params *RequestOTPChallengeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestOTPChallengeNoContent, error)

	VerifyOTP(params *VerifyOTPParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*VerifyOTPOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
	RequestAddressVerification requests address verification

	Generate and send a verification link to the provided address.

The `address` value must be a valid email or mobile number marked as the user's `unverified address` and
must not be a verified address of any other user.

Error `404` is returned when either `userID` or `address` are incorrect.

The requested link validity period is configured in the identity pool settings.
*/
func (a *Client) RequestAddressVerification(params *RequestAddressVerificationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestAddressVerificationNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRequestAddressVerificationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "requestAddressVerification",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/address/verification/request",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RequestAddressVerificationReader{formats: a.formats},
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
	success, ok := result.(*RequestAddressVerificationNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for requestAddressVerification: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	RequestOTPChallenge requests o t p challenge

	Generate and send an OTP to the provided address.

The `address` value must be a valid email or mobile number marked as the user's `unverified address` and
must not be a verified address of any other user.

The requested OTP validity period is configured in the identity pool settings.

Generating new challenge invalidates a previous challenge.
*/
func (a *Client) RequestOTPChallenge(params *RequestOTPChallengeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestOTPChallengeNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRequestOTPChallengeParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "requestOTPChallenge",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/otp/request",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RequestOTPChallengeReader{formats: a.formats},
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
	success, ok := result.(*RequestOTPChallengeNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for requestOTPChallenge: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	VerifyOTP verifies o t p challenge

	Verify the OTP generates as part of a challenge-response mechanism.

A valid OTP is removed, and the endpoint returns the **Request accepted** response.

For password change or activation, call **Request Reset Password** and **Send Activation Message**. Find these
endpoints documented under the **Users** section of this specification.
*/
func (a *Client) VerifyOTP(params *VerifyOTPParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*VerifyOTPOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewVerifyOTPParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "verifyOTP",
		Method:             "POST",
		PathPattern:        "/admin/pools/{ipID}/users/{userID}/otp/verify",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &VerifyOTPReader{formats: a.formats},
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
	success, ok := result.(*VerifyOTPOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for verifyOTP: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
