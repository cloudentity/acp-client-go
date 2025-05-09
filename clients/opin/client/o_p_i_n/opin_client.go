// Code generated by go-swagger; DO NOT EDIT.

package o_p_i_n

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new o p i n API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new o p i n API client with basic auth credentials.
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

// New creates a new o p i n API client with a bearer token for authentication.
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
Client for o p i n API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateInsuranceDataAccessConsent(params *CreateInsuranceDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateInsuranceDataAccessConsentCreated, error)

	DeleteInsuranceDataAccessConsent(params *DeleteInsuranceDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteInsuranceDataAccessConsentNoContent, error)

	GetInsuranceDataAccessConsent(params *GetInsuranceDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetInsuranceDataAccessConsentOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateInsuranceDataAccessConsent creates insurance data access consent

This API allows AISP to create consent to access PSU registration data, information about transactions in their accounts, credit card and contracted credit products
*/
func (a *Client) CreateInsuranceDataAccessConsent(params *CreateInsuranceDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateInsuranceDataAccessConsentCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateInsuranceDataAccessConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateInsuranceDataAccessConsent",
		Method:             "POST",
		PathPattern:        "/open-insurance/consents/v1/",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateInsuranceDataAccessConsentReader{formats: a.formats},
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
	success, ok := result.(*CreateInsuranceDataAccessConsentCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateInsuranceDataAccessConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteInsuranceDataAccessConsent deletes insurance data access consent

This API allows PISP to remove previously created consent
*/
func (a *Client) DeleteInsuranceDataAccessConsent(params *DeleteInsuranceDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteInsuranceDataAccessConsentNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteInsuranceDataAccessConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteInsuranceDataAccessConsent",
		Method:             "DELETE",
		PathPattern:        "/open-insurance/consents/v1/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteInsuranceDataAccessConsentReader{formats: a.formats},
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
	success, ok := result.(*DeleteInsuranceDataAccessConsentNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteInsuranceDataAccessConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetInsuranceDataAccessConsent gets insurance data access consent

This API allows PISP to retrieve previously created consent
*/
func (a *Client) GetInsuranceDataAccessConsent(params *GetInsuranceDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetInsuranceDataAccessConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetInsuranceDataAccessConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetInsuranceDataAccessConsent",
		Method:             "GET",
		PathPattern:        "/open-insurance/consents/v1/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetInsuranceDataAccessConsentReader{formats: a.formats},
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
	success, ok := result.(*GetInsuranceDataAccessConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetInsuranceDataAccessConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
