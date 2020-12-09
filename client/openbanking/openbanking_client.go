// Code generated by go-swagger; DO NOT EDIT.

package openbanking

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new openbanking API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for openbanking API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	AcceptAccountAccessConsentSystem(params *AcceptAccountAccessConsentSystemParams, authInfo runtime.ClientAuthInfoWriter) (*AcceptAccountAccessConsentSystemOK, error)

	CreateAccountAccessConsentRequest(params *CreateAccountAccessConsentRequestParams, authInfo runtime.ClientAuthInfoWriter) (*CreateAccountAccessConsentRequestCreated, error)

	DeleteAccountAccessConsentRequest(params *DeleteAccountAccessConsentRequestParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteAccountAccessConsentRequestNoContent, error)

	GetAccountAccessConsentRequest(params *GetAccountAccessConsentRequestParams, authInfo runtime.ClientAuthInfoWriter) (*GetAccountAccessConsentRequestCreated, error)

	GetAccountAccessConsentSystem(params *GetAccountAccessConsentSystemParams, authInfo runtime.ClientAuthInfoWriter) (*GetAccountAccessConsentSystemOK, error)

	OpenbankingAccountAccessConsentIntrospect(params *OpenbankingAccountAccessConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter) (*OpenbankingAccountAccessConsentIntrospectOK, error)

	RejectAccountAccessConsentSystem(params *RejectAccountAccessConsentSystemParams, authInfo runtime.ClientAuthInfoWriter) (*RejectAccountAccessConsentSystemOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  AcceptAccountAccessConsentSystem accepts account access consent

  This API can be used by a custom openbanking consent page to notify ACP that user granted consent to a given accounts.
*/
func (a *Client) AcceptAccountAccessConsentSystem(params *AcceptAccountAccessConsentSystemParams, authInfo runtime.ClientAuthInfoWriter) (*AcceptAccountAccessConsentSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAcceptAccountAccessConsentSystemParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "acceptAccountAccessConsentSystem",
		Method:             "POST",
		PathPattern:        "/api/system/{tid}/open-banking/account-access-consent/{login}/accept",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AcceptAccountAccessConsentSystemReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*AcceptAccountAccessConsentSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for acceptAccountAccessConsentSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  CreateAccountAccessConsentRequest creates acount access consent

  The API allows the AISP to ask an ASPSP to create a new account-access-consent resource.

This API effectively allows the AISP to send a copy of the consent to the ASPSP to authorize
access to account and transaction information.
An AISP is not able to pre-select a set of accounts for account-access-consent authorisation.
This is because the behavior of the pre-selected accounts, after authorisation, is not clear from a Legal perspective.
An ASPSP creates the account-access-consent resource and responds with a unique ConsentId to
refer to the resource.
Prior to calling the API, the AISP must have an access token issued by the ASPSP using a client
credentials grant.
*/
func (a *Client) CreateAccountAccessConsentRequest(params *CreateAccountAccessConsentRequestParams, authInfo runtime.ClientAuthInfoWriter) (*CreateAccountAccessConsentRequestCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateAccountAccessConsentRequestParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "createAccountAccessConsentRequest",
		Method:             "POST",
		PathPattern:        "/{tid}/{aid}/open-banking/v3.1/aisp/account-access-consents",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateAccountAccessConsentRequestReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateAccountAccessConsentRequestCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createAccountAccessConsentRequest: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteAccountAccessConsentRequest deletes account access consent

  Delete account access consent.
*/
func (a *Client) DeleteAccountAccessConsentRequest(params *DeleteAccountAccessConsentRequestParams, authInfo runtime.ClientAuthInfoWriter) (*DeleteAccountAccessConsentRequestNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteAccountAccessConsentRequestParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deleteAccountAccessConsentRequest",
		Method:             "DELETE",
		PathPattern:        "/{tid}/{aid}/open-banking/v3.1/aisp/account-access-consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteAccountAccessConsentRequestReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteAccountAccessConsentRequestNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteAccountAccessConsentRequest: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAccountAccessConsentRequest gets aconut access consent

  An AISP may optionally retrieve an account-access-consent resource that they have created to check its status.

Prior to calling the API, the AISP must have an access token issued by the ASPSP using a client credentials grant.

The usage of this API endpoint will be subject to an ASPSP's fair usage policies.
*/
func (a *Client) GetAccountAccessConsentRequest(params *GetAccountAccessConsentRequestParams, authInfo runtime.ClientAuthInfoWriter) (*GetAccountAccessConsentRequestCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAccountAccessConsentRequestParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getAccountAccessConsentRequest",
		Method:             "GET",
		PathPattern:        "/{tid}/{aid}/open-banking/v3.1/aisp/account-access-consents/{consentID}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAccountAccessConsentRequestReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAccountAccessConsentRequestCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getAccountAccessConsentRequest: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetAccountAccessConsentSystem gets account access consent

  This API can be used by a custom openbanking consent page.
The consent page must first use client credentials flow to create account access consent.
*/
func (a *Client) GetAccountAccessConsentSystem(params *GetAccountAccessConsentSystemParams, authInfo runtime.ClientAuthInfoWriter) (*GetAccountAccessConsentSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAccountAccessConsentSystemParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getAccountAccessConsentSystem",
		Method:             "GET",
		PathPattern:        "/api/system/{tid}/open-banking/account-access-consent/{login}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAccountAccessConsentSystemReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetAccountAccessConsentSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getAccountAccessConsentSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  OpenbankingAccountAccessConsentIntrospect introspects openbanking account access consent

  Introspect openbanking account access consent.
*/
func (a *Client) OpenbankingAccountAccessConsentIntrospect(params *OpenbankingAccountAccessConsentIntrospectParams, authInfo runtime.ClientAuthInfoWriter) (*OpenbankingAccountAccessConsentIntrospectOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewOpenbankingAccountAccessConsentIntrospectParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "openbankingAccountAccessConsentIntrospect",
		Method:             "POST",
		PathPattern:        "/{tid}/{aid}/open-banking/v3.1/aisp/account-access-consents/introspect",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &OpenbankingAccountAccessConsentIntrospectReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*OpenbankingAccountAccessConsentIntrospectOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for openbankingAccountAccessConsentIntrospect: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RejectAccountAccessConsentSystem rejects account access consent

  This API can be used by a custom openbanking consent page to notify ACP that user rejected access to accounts.
*/
func (a *Client) RejectAccountAccessConsentSystem(params *RejectAccountAccessConsentSystemParams, authInfo runtime.ClientAuthInfoWriter) (*RejectAccountAccessConsentSystemOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRejectAccountAccessConsentSystemParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "rejectAccountAccessConsentSystem",
		Method:             "POST",
		PathPattern:        "/api/system/{tid}/open-banking/account-access-consent/{login}/reject",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RejectAccountAccessConsentSystemReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*RejectAccountAccessConsentSystemOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for rejectAccountAccessConsentSystem: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
