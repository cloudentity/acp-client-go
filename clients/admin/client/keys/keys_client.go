// Code generated by go-swagger; DO NOT EDIT.

package keys

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new keys API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new keys API client with basic auth credentials.
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

// New creates a new keys API client with a bearer token for authentication.
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
Client for keys API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetAutomaticKeyRotation(params *GetAutomaticKeyRotationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAutomaticKeyRotationOK, error)

	GetKey(params *GetKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetKeyOK, error)

	GetKeys(params *GetKeysParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetKeysOK, error)

	RevokeKey(params *RevokeKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeKeyOK, error)

	RotateKey(params *RotateKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RotateKeyOK, error)

	SetAutomaticKeyRotation(params *SetAutomaticKeyRotationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetAutomaticKeyRotationOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetAutomaticKeyRotation gets automatic key rotation

Get automatic key rotation configuration.
*/
func (a *Client) GetAutomaticKeyRotation(params *GetAutomaticKeyRotationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetAutomaticKeyRotationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetAutomaticKeyRotationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getAutomaticKeyRotation",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/keys/automatic-key-rotation",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetAutomaticKeyRotationReader{formats: a.formats},
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
	success, ok := result.(*GetAutomaticKeyRotationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getAutomaticKeyRotation: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetKey gets server key by kid

Get next, current or rotated server key by kid and return as raw jwk without metadata.
*/
func (a *Client) GetKey(params *GetKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetKeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getKey",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/keys/{kid}/raw",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetKeyReader{formats: a.formats},
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
	success, ok := result.(*GetKeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getKey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetKeys gets server keys

Get server encryption or signing keys.
*/
func (a *Client) GetKeys(params *GetKeysParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetKeysOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetKeysParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getKeys",
		Method:             "GET",
		PathPattern:        "/servers/{wid}/keys",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetKeysReader{formats: a.formats},
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
	success, ok := result.(*GetKeysOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getKeys: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RevokeKey revokes key

Revoke rotated key
*/
func (a *Client) RevokeKey(params *RevokeKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RevokeKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRevokeKeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "revokeKey",
		Method:             "POST",
		PathPattern:        "/servers/{wid}/keys/revoke/{kid}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RevokeKeyReader{formats: a.formats},
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
	success, ok := result.(*RevokeKeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for revokeKey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RotateKey rotates key

Rotate encryption or signing key.
*/
func (a *Client) RotateKey(params *RotateKeyParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RotateKeyOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRotateKeyParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "rotateKey",
		Method:             "POST",
		PathPattern:        "/servers/{wid}/keys/rotate",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RotateKeyReader{formats: a.formats},
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
	success, ok := result.(*RotateKeyOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for rotateKey: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SetAutomaticKeyRotation sets automatic key rotation

Set automatic key rotation configuration.
*/
func (a *Client) SetAutomaticKeyRotation(params *SetAutomaticKeyRotationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SetAutomaticKeyRotationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSetAutomaticKeyRotationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "setAutomaticKeyRotation",
		Method:             "PUT",
		PathPattern:        "/servers/{wid}/keys/automatic-key-rotation",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SetAutomaticKeyRotationReader{formats: a.formats},
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
	success, ok := result.(*SetAutomaticKeyRotationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for setAutomaticKeyRotation: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
