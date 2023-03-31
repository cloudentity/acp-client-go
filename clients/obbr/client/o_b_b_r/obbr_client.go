// Code generated by go-swagger; DO NOT EDIT.

package o_b_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new o b b r API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for o b b r API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateDataAccessConsent(params *CreateDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateDataAccessConsentCreated, error)

	CreateDataAccessConsentDeprecated(params *CreateDataAccessConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateDataAccessConsentDeprecatedCreated, error)

	CreateDataAccessConsentV2(params *CreateDataAccessConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateDataAccessConsentV2Created, error)

	CreatePaymentConsent(params *CreatePaymentConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePaymentConsentCreated, error)

	CreatePaymentConsentDeprecated(params *CreatePaymentConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePaymentConsentDeprecatedCreated, error)

	CreatePaymentConsentV2(params *CreatePaymentConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePaymentConsentV2Created, error)

	DeleteDataAccessConsent(params *DeleteDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteDataAccessConsentNoContent, error)

	DeleteDataAccessConsentDeprecated(params *DeleteDataAccessConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteDataAccessConsentDeprecatedNoContent, error)

	DeleteDataAccessConsentV2(params *DeleteDataAccessConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteDataAccessConsentV2NoContent, error)

	GetDataAccessConsent(params *GetDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDataAccessConsentOK, error)

	GetDataAccessConsentDeprecated(params *GetDataAccessConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDataAccessConsentDeprecatedOK, error)

	GetDataAccessConsentV2(params *GetDataAccessConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDataAccessConsentV2OK, error)

	GetPaymentConsent(params *GetPaymentConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPaymentConsentOK, error)

	GetPaymentConsentDeprecated(params *GetPaymentConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPaymentConsentDeprecatedOK, error)

	GetPaymentConsentV2(params *GetPaymentConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPaymentConsentV2OK, error)

	PatchPaymentConsent(params *PatchPaymentConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PatchPaymentConsentOK, error)

	ObbrDataAccessConsentIntrospect(params *ObbrDataAccessConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrDataAccessConsentIntrospectOK, error)

	ObbrDataAccessConsentV2Introspect(params *ObbrDataAccessConsentV2IntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrDataAccessConsentV2IntrospectOK, error)

	ObbrPaymentConsentIntrospect(params *ObbrPaymentConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrPaymentConsentIntrospectOK, error)

	ObbrPaymentConsentIntrospectV2(params *ObbrPaymentConsentIntrospectV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrPaymentConsentIntrospectV2OK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateDataAccessConsent creates data access consent

This API allows AISP to create consent to access PSU registration data, information about transactions in their accounts, credit card and contracted credit products
*/
func (a *Client) CreateDataAccessConsent(params *CreateDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateDataAccessConsentCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateDataAccessConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateDataAccessConsent",
		Method:             "POST",
		PathPattern:        "/open-banking/consents/v1/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateDataAccessConsentReader{formats: a.formats},
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
	success, ok := result.(*CreateDataAccessConsentCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateDataAccessConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateDataAccessConsentDeprecated creates data access consent

This API allows AISP to create consent to access PSU registration data, information about transactions in their accounts, credit card and contracted credit products
*/
func (a *Client) CreateDataAccessConsentDeprecated(params *CreateDataAccessConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateDataAccessConsentDeprecatedCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateDataAccessConsentDeprecatedParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateDataAccessConsentDeprecated",
		Method:             "POST",
		PathPattern:        "/open-banking-brasil/open-banking/consents/v1/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateDataAccessConsentDeprecatedReader{formats: a.formats},
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
	success, ok := result.(*CreateDataAccessConsentDeprecatedCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateDataAccessConsentDeprecated: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateDataAccessConsentV2 creates data access consent

This API allows AISP to create consent to access PSU registration data, information about transactions in their accounts, credit card and contracted credit products
*/
func (a *Client) CreateDataAccessConsentV2(params *CreateDataAccessConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateDataAccessConsentV2Created, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateDataAccessConsentV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateDataAccessConsentV2",
		Method:             "POST",
		PathPattern:        "/open-banking/consents/v2/consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateDataAccessConsentV2Reader{formats: a.formats},
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
	success, ok := result.(*CreateDataAccessConsentV2Created)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateDataAccessConsentV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreatePaymentConsent creates payment consent

This API allows AISP to create consent to initiate payments between banks and financial institutions
*/
func (a *Client) CreatePaymentConsent(params *CreatePaymentConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePaymentConsentCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreatePaymentConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreatePaymentConsent",
		Method:             "POST",
		PathPattern:        "/open-banking/payments/v1/consents",
		ProducesMediaTypes: []string{"application/jwt"},
		ConsumesMediaTypes: []string{"application/jwt"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreatePaymentConsentReader{formats: a.formats},
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
	success, ok := result.(*CreatePaymentConsentCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreatePaymentConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreatePaymentConsentDeprecated creates payment consent

This API allows AISP to create consent to initiate payments between banks and financial institutions
*/
func (a *Client) CreatePaymentConsentDeprecated(params *CreatePaymentConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePaymentConsentDeprecatedCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreatePaymentConsentDeprecatedParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreatePaymentConsentDeprecated",
		Method:             "POST",
		PathPattern:        "/open-banking-brasil/open-banking/payments/v1/consents",
		ProducesMediaTypes: []string{"application/jwt"},
		ConsumesMediaTypes: []string{"application/jwt"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreatePaymentConsentDeprecatedReader{formats: a.formats},
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
	success, ok := result.(*CreatePaymentConsentDeprecatedCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreatePaymentConsentDeprecated: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreatePaymentConsentV2 creates payment consent

This API allows AISP to create consent to initiate payments between banks and financial institutions
*/
func (a *Client) CreatePaymentConsentV2(params *CreatePaymentConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreatePaymentConsentV2Created, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreatePaymentConsentV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreatePaymentConsentV2",
		Method:             "POST",
		PathPattern:        "/open-banking/payments/v2/consents",
		ProducesMediaTypes: []string{"application/jwt"},
		ConsumesMediaTypes: []string{"application/jwt"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreatePaymentConsentV2Reader{formats: a.formats},
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
	success, ok := result.(*CreatePaymentConsentV2Created)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreatePaymentConsentV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteDataAccessConsent deletes data access consent

This API allows PISP to remove previously created consent
*/
func (a *Client) DeleteDataAccessConsent(params *DeleteDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteDataAccessConsentNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteDataAccessConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteDataAccessConsent",
		Method:             "DELETE",
		PathPattern:        "/open-banking/consents/v1/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteDataAccessConsentReader{formats: a.formats},
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
	success, ok := result.(*DeleteDataAccessConsentNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteDataAccessConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteDataAccessConsentDeprecated deletes data access consent

This API allows PISP to remove previously created consent
*/
func (a *Client) DeleteDataAccessConsentDeprecated(params *DeleteDataAccessConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteDataAccessConsentDeprecatedNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteDataAccessConsentDeprecatedParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteDataAccessConsentDeprecated",
		Method:             "DELETE",
		PathPattern:        "/open-banking-brasil/open-banking/consents/v1/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteDataAccessConsentDeprecatedReader{formats: a.formats},
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
	success, ok := result.(*DeleteDataAccessConsentDeprecatedNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteDataAccessConsentDeprecated: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteDataAccessConsentV2 deletes data access consent

This API allows PISP to remove previously created consent
*/
func (a *Client) DeleteDataAccessConsentV2(params *DeleteDataAccessConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteDataAccessConsentV2NoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteDataAccessConsentV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteDataAccessConsentV2",
		Method:             "DELETE",
		PathPattern:        "/open-banking/consents/v2/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteDataAccessConsentV2Reader{formats: a.formats},
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
	success, ok := result.(*DeleteDataAccessConsentV2NoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteDataAccessConsentV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetDataAccessConsent gets data access consent

This API allows PISP to retrieve previously created consent
*/
func (a *Client) GetDataAccessConsent(params *GetDataAccessConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDataAccessConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetDataAccessConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetDataAccessConsent",
		Method:             "GET",
		PathPattern:        "/open-banking/consents/v1/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetDataAccessConsentReader{formats: a.formats},
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
	success, ok := result.(*GetDataAccessConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetDataAccessConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetDataAccessConsentDeprecated gets data access consent

This API allows PISP to retrieve previously created consent
*/
func (a *Client) GetDataAccessConsentDeprecated(params *GetDataAccessConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDataAccessConsentDeprecatedOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetDataAccessConsentDeprecatedParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetDataAccessConsentDeprecated",
		Method:             "GET",
		PathPattern:        "/open-banking-brasil/open-banking/consents/v1/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetDataAccessConsentDeprecatedReader{formats: a.formats},
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
	success, ok := result.(*GetDataAccessConsentDeprecatedOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetDataAccessConsentDeprecated: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetDataAccessConsentV2 gets data access consent

This API allows PISP to retrieve previously created consent
*/
func (a *Client) GetDataAccessConsentV2(params *GetDataAccessConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDataAccessConsentV2OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetDataAccessConsentV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetDataAccessConsentV2",
		Method:             "GET",
		PathPattern:        "/open-banking/consents/v2/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetDataAccessConsentV2Reader{formats: a.formats},
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
	success, ok := result.(*GetDataAccessConsentV2OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetDataAccessConsentV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetPaymentConsent gets payment consent

This API allows PISP to retrieve previously created payment consent
*/
func (a *Client) GetPaymentConsent(params *GetPaymentConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPaymentConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPaymentConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetPaymentConsent",
		Method:             "GET",
		PathPattern:        "/open-banking/payments/v1/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetPaymentConsentReader{formats: a.formats},
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
	success, ok := result.(*GetPaymentConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetPaymentConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetPaymentConsentDeprecated gets payment consent

This API allows PISP to retrieve previously created payment consent
*/
func (a *Client) GetPaymentConsentDeprecated(params *GetPaymentConsentDeprecatedParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPaymentConsentDeprecatedOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPaymentConsentDeprecatedParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetPaymentConsentDeprecated",
		Method:             "GET",
		PathPattern:        "/open-banking-brasil/open-banking/payments/v1/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetPaymentConsentDeprecatedReader{formats: a.formats},
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
	success, ok := result.(*GetPaymentConsentDeprecatedOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetPaymentConsentDeprecated: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetPaymentConsentV2 gets payment consent

This API allows PISP to retrieve previously created payment consent
*/
func (a *Client) GetPaymentConsentV2(params *GetPaymentConsentV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetPaymentConsentV2OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPaymentConsentV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetPaymentConsentV2",
		Method:             "GET",
		PathPattern:        "/open-banking/payments/v2/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetPaymentConsentV2Reader{formats: a.formats},
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
	success, ok := result.(*GetPaymentConsentV2OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetPaymentConsentV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
PatchPaymentConsent revokes payment consent

This API allows PISP to revoke a payment consent
*/
func (a *Client) PatchPaymentConsent(params *PatchPaymentConsentParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PatchPaymentConsentOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchPaymentConsentParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PatchPaymentConsent",
		Method:             "PATCH",
		PathPattern:        "/open-banking/payments/v1/consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PatchPaymentConsentReader{formats: a.formats},
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
	success, ok := result.(*PatchPaymentConsentOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for PatchPaymentConsent: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ObbrDataAccessConsentIntrospect introspects openbanking brasil data access consent

Introspect openbanking brasil data access consent
*/
func (a *Client) ObbrDataAccessConsentIntrospect(params *ObbrDataAccessConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrDataAccessConsentIntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewObbrDataAccessConsentIntrospectParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "obbrDataAccessConsentIntrospect",
		Method:             "POST",
		PathPattern:        "/open-banking-brasil/open-banking/consents/v1/consents/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ObbrDataAccessConsentIntrospectReader{formats: a.formats},
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
	success, ok := result.(*ObbrDataAccessConsentIntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for obbrDataAccessConsentIntrospect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ObbrDataAccessConsentV2Introspect introspects openbanking brasil data access consent

This API allows introspection of tokens bound to v2 consents. It is also backwards compatible with v1 consent tokens.
*/
func (a *Client) ObbrDataAccessConsentV2Introspect(params *ObbrDataAccessConsentV2IntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrDataAccessConsentV2IntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewObbrDataAccessConsentV2IntrospectParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "obbrDataAccessConsentV2Introspect",
		Method:             "POST",
		PathPattern:        "/open-banking-brasil/open-banking/consents/v2/consents/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ObbrDataAccessConsentV2IntrospectReader{formats: a.formats},
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
	success, ok := result.(*ObbrDataAccessConsentV2IntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for obbrDataAccessConsentV2Introspect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
	ObbrPaymentConsentIntrospect introspects openbanking brasil payment consent

	This endpoint takes an OAuth 2.0 token and, in addition to returning

meta information surrounding the token, returns the payment consent and
associated account ids.
*/
func (a *Client) ObbrPaymentConsentIntrospect(params *ObbrPaymentConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrPaymentConsentIntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewObbrPaymentConsentIntrospectParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "obbrPaymentConsentIntrospect",
		Method:             "POST",
		PathPattern:        "/open-banking-brasil/open-banking/payments/v1/consents/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ObbrPaymentConsentIntrospectReader{formats: a.formats},
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
	success, ok := result.(*ObbrPaymentConsentIntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for obbrPaymentConsentIntrospect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ObbrPaymentConsentIntrospectV2 introspects openbanking brasil payment consent

This API allows introspection of tokens bound to v2 payment consents. It is also backwards compatible with v1 payment consent tokens.
*/
func (a *Client) ObbrPaymentConsentIntrospectV2(params *ObbrPaymentConsentIntrospectV2Params, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ObbrPaymentConsentIntrospectV2OK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewObbrPaymentConsentIntrospectV2Params()
	}
	op := &runtime.ClientOperation{
		ID:                 "obbrPaymentConsentIntrospectV2",
		Method:             "POST",
		PathPattern:        "/open-banking-brasil/open-banking/payments/v2/consents/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ObbrPaymentConsentIntrospectV2Reader{formats: a.formats},
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
	success, ok := result.(*ObbrPaymentConsentIntrospectV2OK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for obbrPaymentConsentIntrospectV2: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
