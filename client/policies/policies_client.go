// Code generated by go-swagger; DO NOT EDIT.

package policies

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new policies API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for policies API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	CreatePolicy(params *CreatePolicyParams, authInfo runtime.ClientAuthInfoWriter) (*CreatePolicyCreated, error)

	DeletePolicy(params *DeletePolicyParams, authInfo runtime.ClientAuthInfoWriter) (*DeletePolicyNoContent, error)

	GetPolicy(params *GetPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*GetPolicyOK, error)

	ListPolicies(params *ListPoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListPoliciesOK, error)

	ListPolicyExecutionPoints(params *ListPolicyExecutionPointsParams, authInfo runtime.ClientAuthInfoWriter) (*ListPolicyExecutionPointsOK, error)

	SetPolicyExecutionPoints(params *SetPolicyExecutionPointsParams, authInfo runtime.ClientAuthInfoWriter) (*SetPolicyExecutionPointsOK, error)

	TestPolicy(params *TestPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*TestPolicyOK, error)

	UpdatePolicy(params *UpdatePolicyParams, authInfo runtime.ClientAuthInfoWriter) (*UpdatePolicyCreated, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreatePolicy creates policy

  Policies are created per tenant.

ID and Name are required fields.

Sample validators which can be used to build policies: identity-context, consent, header, true, false.
*/
func (a *Client) CreatePolicy(params *CreatePolicyParams, authInfo runtime.ClientAuthInfoWriter) (*CreatePolicyCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreatePolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "createPolicy",
		Method:             "POST",
		PathPattern:        "/api/admin/{tid}/policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreatePolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreatePolicyCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeletePolicy deletes policy

  Delete policy.

A policy can't be removed if it's in use.
*/
func (a *Client) DeletePolicy(params *DeletePolicyParams, authInfo runtime.ClientAuthInfoWriter) (*DeletePolicyNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeletePolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "deletePolicy",
		Method:             "DELETE",
		PathPattern:        "/api/admin/{tid}/policies/{pid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeletePolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeletePolicyNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deletePolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetPolicy gets policy

  Get policy.
*/
func (a *Client) GetPolicy(params *GetPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*GetPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetPolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "getPolicy",
		Method:             "GET",
		PathPattern:        "/api/admin/{tid}/policies/{pid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetPolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListPolicies lists policies

  List server policies by type.
*/
func (a *Client) ListPolicies(params *ListPoliciesParams, authInfo runtime.ClientAuthInfoWriter) (*ListPoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListPoliciesParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listPolicies",
		Method:             "GET",
		PathPattern:        "/api/admin/{tid}/servers/{aid}/policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListPoliciesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListPoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listPolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListPolicyExecutionPoints lists policy execution points

  List policy execution points.
*/
func (a *Client) ListPolicyExecutionPoints(params *ListPolicyExecutionPointsParams, authInfo runtime.ClientAuthInfoWriter) (*ListPolicyExecutionPointsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListPolicyExecutionPointsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "listPolicyExecutionPoints",
		Method:             "GET",
		PathPattern:        "/api/admin/{tid}/servers/{aid}/policy-execution-points",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListPolicyExecutionPointsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListPolicyExecutionPointsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listPolicyExecutionPoints: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  SetPolicyExecutionPoints sets policy execution points

  Set policy execution points.

Available execution points:
scope_client_assignment
scope_user_grant
server_client_assignment
server_user_token
client_user_token
api
*/
func (a *Client) SetPolicyExecutionPoints(params *SetPolicyExecutionPointsParams, authInfo runtime.ClientAuthInfoWriter) (*SetPolicyExecutionPointsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetPolicyExecutionPointsParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "setPolicyExecutionPoints",
		Method:             "PUT",
		PathPattern:        "/api/admin/{tid}/servers/{aid}/policy-execution-points",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetPolicyExecutionPointsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*SetPolicyExecutionPointsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setPolicyExecutionPoints: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  TestPolicy tests policy

  Test policy.
*/
func (a *Client) TestPolicy(params *TestPolicyParams, authInfo runtime.ClientAuthInfoWriter) (*TestPolicyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewTestPolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "testPolicy",
		Method:             "POST",
		PathPattern:        "/api/admin/{tid}/policies/test",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &TestPolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*TestPolicyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for testPolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdatePolicy updates policy

  Update policy.
*/
func (a *Client) UpdatePolicy(params *UpdatePolicyParams, authInfo runtime.ClientAuthInfoWriter) (*UpdatePolicyCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdatePolicyParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "updatePolicy",
		Method:             "PUT",
		PathPattern:        "/api/admin/{tid}/policies/{pid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdatePolicyReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*UpdatePolicyCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updatePolicy: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
