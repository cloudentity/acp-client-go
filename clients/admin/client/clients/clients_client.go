// Code generated by go-swagger; DO NOT EDIT.

package clients

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new clients API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for clients API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateClient(params *CreateClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateClientCreated, error)

	DeleteClient(params *DeleteClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteClientNoContent, error)

	GetClient(params *GetClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetClientOK, error)

	ListClients(params *ListClientsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListClientsOK, error)

	RevokeRotatedClientSecrets(params *RevokeRotatedClientSecretsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeRotatedClientSecretsNoContent, error)

	RotateClientSecret(params *RotateClientSecretParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RotateClientSecretOK, error)

	UpdateClient(params *UpdateClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateClientOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  CreateClient creates new o auth client

  Client must be created under existing tenant and authorization server.

Authorization server id must be provided in the request body.

Client id and secret can be provided, otherwise are generated.

If grant type is not set, client will get authorization code grant type assigned with code as response type.

Default token authentication method is client_secret_basic.
*/
func (a *Client) CreateClient(params *CreateClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateClientCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createClient",
		Method:             "POST",
		PathPattern:        "/clients",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateClientReader{formats: a.formats},
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
	success, ok := result.(*CreateClientCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteClient deletes client

  Delete client.
*/
func (a *Client) DeleteClient(params *DeleteClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteClientNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteClient",
		Method:             "DELETE",
		PathPattern:        "/clients/{cid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteClientReader{formats: a.formats},
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
	success, ok := result.(*DeleteClientNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetClient gets client

  If client has been created by a developer, client's secret will be empty.
*/
func (a *Client) GetClient(params *GetClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getClient",
		Method:             "GET",
		PathPattern:        "/clients/{cid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetClientReader{formats: a.formats},
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
	success, ok := result.(*GetClientOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListClients lists clients

  Returns clients created by admins and developers. If client has been created by a developer, client secret will be empty.
*/
func (a *Client) ListClients(params *ListClientsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListClientsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListClientsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listClients",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/clients",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListClientsReader{formats: a.formats},
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
	success, ok := result.(*ListClientsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listClients: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RevokeRotatedClientSecrets revokes rotated secrets

  Revoke all rotated client's secrets.
*/
func (a *Client) RevokeRotatedClientSecrets(params *RevokeRotatedClientSecretsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeRotatedClientSecretsNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeRotatedClientSecretsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeRotatedClientSecrets",
		Method:             "POST",
		PathPattern:        "/clients/{cid}/revokeRotatedSecrets",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeRotatedClientSecretsReader{formats: a.formats},
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
	success, ok := result.(*RevokeRotatedClientSecretsNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeRotatedClientSecrets: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RotateClientSecret rotates client s secret

  Generate a new client secret, move old secret to rotated secrets list and return
new client secret as a response. The max number of client rotated secrets is 2.
The rotated secrets over the limit are dropped.

It is possible to set expiration time for rotated secrets. When the `AutoRevokeAfter` parameter
is set to a value greater than zero, rotated secrets that reach their expiry time are revoked.
The `AutoRevokeAfter` parameter accepts values in the go-openapi duration format, for example,
`1s`, `5m`, `2h`.
*/
func (a *Client) RotateClientSecret(params *RotateClientSecretParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RotateClientSecretOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRotateClientSecretParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "rotateClientSecret",
		Method:             "POST",
		PathPattern:        "/clients/{cid}/rotateSecret",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RotateClientSecretReader{formats: a.formats},
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
	success, ok := result.(*RotateClientSecretOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for rotateClientSecret: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateClient updates client

  Update client.

For clients created by developers only metadata, system and trusted attributes
can be updated.
*/
func (a *Client) UpdateClient(params *UpdateClientParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateClientOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateClientParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateClient",
		Method:             "PUT",
		PathPattern:        "/clients/{cid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateClientReader{formats: a.formats},
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
	success, ok := result.(*UpdateClientOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateClient: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}