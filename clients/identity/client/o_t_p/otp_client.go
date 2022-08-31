// Code generated by go-swagger; DO NOT EDIT.

package o_t_p

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new o t p API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for o t p API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CompleteAddressVerification(params *CompleteAddressVerificationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CompleteAddressVerificationNoContent, error)

	InspectOTP(params *InspectOTPParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*InspectOTPOK, error)

	RequestAddressVerification(params *RequestAddressVerificationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestAddressVerificationNoContent, error)

	RequestOTPChallenge(params *RequestOTPChallengeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestOTPChallengeNoContent, error)

	VerifyOTP(params *VerifyOTPParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*VerifyOTPOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CompleteAddressVerification completes address verification

  Completes unverified address verification by checking if code is valid or not.
Both address and code must be provided.
Fails if address is not user's address or is user's verified or is someone's verified address.
If the OTP is valid it is removed and a successful response is returned.
Endpoint is protected by Brute Force mechanism.
*/
func (a *Client) CompleteAddressVerification(params *CompleteAddressVerificationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CompleteAddressVerificationNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCompleteAddressVerificationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "completeAddressVerification",
		Method:             "POST",
		PathPattern:        "/system/pools/{ipID}/users/{userID}/address/verification/complete",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CompleteAddressVerificationReader{formats: a.formats},
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
	success, ok := result.(*CompleteAddressVerificationNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for completeAddressVerification: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  InspectOTP inspects extended o t p

  Verifies if the provided extended OTP is valid and returns basic user operational data.
Endpoint is protected by Brute Force mechanism.
This endpoint is meant for UI integration during user activation.
*/
func (a *Client) InspectOTP(params *InspectOTPParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*InspectOTPOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewInspectOTPParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "inspectOTP",
		Method:             "POST",
		PathPattern:        "/system/pools/{ipID}/user/otp/inspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &InspectOTPReader{formats: a.formats},
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
	success, ok := result.(*InspectOTPOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for inspectOTP: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RequestAddressVerification requests address verification

  Generates and sends verification code to the provided address.
Identifier must be a valid email or mobile which is marked as an unverified address for the user and is not someone's verified address.
If address is someone's verified address, the request ends successfully to prevent email/mobile enumeration.
Requested code is valid for specific period of time configured in Identity Pool.
*/
func (a *Client) RequestAddressVerification(params *RequestAddressVerificationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestAddressVerificationNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRequestAddressVerificationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "requestAddressVerification",
		Method:             "POST",
		PathPattern:        "/system/pools/{ipID}/users/{userID}/address/verification/request",
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

  Generates and sends OTP to the provided identifier.
Identifier must be a valid email or mobile which is marked as a verified address for the user.
For validating unverified address userID must be provided.
When both userID and identifier are provided then address matching identifier is taken from user pointed by userID.
Regardless if the identifier points to some user or not, the request ends successfully to prevent email/mobile enumeration.
Requested OTP is valid for specific period of time configured in Identity Pool.
Generating new challenge invalidates previous challenge.
*/
func (a *Client) RequestOTPChallenge(params *RequestOTPChallengeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RequestOTPChallengeNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRequestOTPChallengeParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "requestOTPChallenge",
		Method:             "POST",
		PathPattern:        "/system/pools/{ipID}/user/otp/request",
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

  Verifies if the provided OTP is valid or not.
This API is meant for challenge OTPs, not for activation or password change.
Either identifier (must be user's identifier), user id or extended code must be provided.
If the OTP is valid it is removed and a successful response is returned.
Endpoint is protected by Brute Force mechanism.
This endpoint is meant for integration when external system requests and verifies OTP.
*/
func (a *Client) VerifyOTP(params *VerifyOTPParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*VerifyOTPOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewVerifyOTPParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "verifyOTP",
		Method:             "POST",
		PathPattern:        "/system/pools/{ipID}/user/otp/verify",
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