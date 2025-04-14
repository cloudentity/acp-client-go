// Code generated by go-swagger; DO NOT EDIT.

package templates

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new templates API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new templates API client with basic auth credentials.
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

// New creates a new templates API client with a bearer token for authentication.
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
Client for templates API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// This client is generated with a few options you might find useful for your swagger spec.
//
// Feel free to add you own set of options.

// WithContentType allows the client to force the Content-Type header
// to negotiate a specific Consumer from the server.
//
// You may use this option to set arbitrary extensions to your MIME media type.
func WithContentType(mime string) ClientOption {
	return func(r *runtime.ClientOperation) {
		r.ConsumesMediaTypes = []string{mime}
	}
}

// WithContentTypeApplicationJSON sets the Content-Type header to "application/json".
func WithContentTypeApplicationJSON(r *runtime.ClientOperation) {
	r.ConsumesMediaTypes = []string{"application/json"}
}

// WithContentTypeApplicationZip sets the Content-Type header to "application/zip".
func WithContentTypeApplicationZip(r *runtime.ClientOperation) {
	r.ConsumesMediaTypes = []string{"application/zip"}
}

// WithAccept allows the client to force the Accept header
// to negotiate a specific Producer from the server.
//
// You may use this option to set arbitrary extensions to your MIME media type.
func WithAccept(mime string) ClientOption {
	return func(r *runtime.ClientOperation) {
		r.ProducesMediaTypes = []string{mime}
	}
}

// WithAcceptApplicationJSON sets the Accept header to "application/json".
func WithAcceptApplicationJSON(r *runtime.ClientOperation) {
	r.ProducesMediaTypes = []string{"application/json"}
}

// WithAcceptApplicationZip sets the Accept header to "application/zip".
func WithAcceptApplicationZip(r *runtime.ClientOperation) {
	r.ProducesMediaTypes = []string{"application/zip"}
}

// ClientService is the interface for Client methods
type ClientService interface {
	DeleteTemplate(params *DeleteTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteTemplateNoContent, error)

	ExportThemeTemplates(params *ExportThemeTemplatesParams, authInfo runtime.ClientAuthInfoWriter, writer io.Writer, opts ...ClientOption) (*ExportThemeTemplatesOK, error)

	GetDefaultTemplate(params *GetDefaultTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDefaultTemplateOK, error)

	GetTemplate(params *GetTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetTemplateOK, error)

	ImportThemeTemplates(params *ImportThemeTemplatesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ImportThemeTemplatesNoContent, error)

	ListDefaultTemplates(params *ListDefaultTemplatesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListDefaultTemplatesOK, error)

	ListThemeTemplates(params *ListThemeTemplatesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListThemeTemplatesOK, error)

	UpsertTemplate(params *UpsertTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpsertTemplateOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
DeleteTemplate deletes template

Deletes the custom-branding template.
*/
func (a *Client) DeleteTemplate(params *DeleteTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteTemplateNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteTemplateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteTemplate",
		Method:             "DELETE",
		PathPattern:        "/theme/{themeID}/template/{fsPath}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteTemplateReader{formats: a.formats},
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
	success, ok := result.(*DeleteTemplateNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteTemplate: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExportThemeTemplates exports templates

Returns the theme's templates in a Zip archive.
*/
func (a *Client) ExportThemeTemplates(params *ExportThemeTemplatesParams, authInfo runtime.ClientAuthInfoWriter, writer io.Writer, opts ...ClientOption) (*ExportThemeTemplatesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExportThemeTemplatesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "exportThemeTemplates",
		Method:             "GET",
		PathPattern:        "/theme/{themeID}/templates/zip",
		ProducesMediaTypes: []string{"application/zip"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExportThemeTemplatesReader{formats: a.formats, writer: writer},
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
	success, ok := result.(*ExportThemeTemplatesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for exportThemeTemplates: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetDefaultTemplate gets default template

Returns the default, builtin Template and its content.
*/
func (a *Client) GetDefaultTemplate(params *GetDefaultTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetDefaultTemplateOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetDefaultTemplateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getDefaultTemplate",
		Method:             "GET",
		PathPattern:        "/themes/template/{fsPath}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetDefaultTemplateReader{formats: a.formats},
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
	success, ok := result.(*GetDefaultTemplateOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getDefaultTemplate: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetTemplate gets template

Returns an Template and its content.
*/
func (a *Client) GetTemplate(params *GetTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetTemplateOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetTemplateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getTemplate",
		Method:             "GET",
		PathPattern:        "/theme/{themeID}/template/{fsPath}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetTemplateReader{formats: a.formats},
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
	success, ok := result.(*GetTemplateOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getTemplate: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ImportThemeTemplates imports templates

Imports the theme's templates from a Zip archive.
*/
func (a *Client) ImportThemeTemplates(params *ImportThemeTemplatesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ImportThemeTemplatesNoContent, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewImportThemeTemplatesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "importThemeTemplates",
		Method:             "POST",
		PathPattern:        "/theme/{themeID}/templates/zip",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/zip"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ImportThemeTemplatesReader{formats: a.formats},
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
	success, ok := result.(*ImportThemeTemplatesNoContent)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for importThemeTemplates: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListDefaultTemplates lists default templates

Returns the file-system paths (fs_path) for all of the default built-in templates.
*/
func (a *Client) ListDefaultTemplates(params *ListDefaultTemplatesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListDefaultTemplatesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListDefaultTemplatesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listDefaultTemplates",
		Method:             "GET",
		PathPattern:        "/themes/templates",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListDefaultTemplatesReader{formats: a.formats},
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
	success, ok := result.(*ListDefaultTemplatesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listDefaultTemplates: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ListThemeTemplates lists templates

This API returns the file-system paths (fs_path) for all of the templates in the theme.
*/
func (a *Client) ListThemeTemplates(params *ListThemeTemplatesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListThemeTemplatesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListThemeTemplatesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listThemeTemplates",
		Method:             "GET",
		PathPattern:        "/theme/{themeID}/templates",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListThemeTemplatesReader{formats: a.formats},
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
	success, ok := result.(*ListThemeTemplatesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listThemeTemplates: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpsertTemplate updates or insert template

Updates an existing custom branding template, or inserts a new one.
*/
func (a *Client) UpsertTemplate(params *UpsertTemplateParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpsertTemplateOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpsertTemplateParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "upsertTemplate",
		Method:             "PUT",
		PathPattern:        "/theme/{themeID}/template/{fsPath}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpsertTemplateReader{formats: a.formats},
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
	success, ok := result.(*UpsertTemplateOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for upsertTemplate: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
