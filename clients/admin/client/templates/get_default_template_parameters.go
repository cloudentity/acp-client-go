// Code generated by go-swagger; DO NOT EDIT.

package templates

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewGetDefaultTemplateParams creates a new GetDefaultTemplateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetDefaultTemplateParams() *GetDefaultTemplateParams {
	return &GetDefaultTemplateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetDefaultTemplateParamsWithTimeout creates a new GetDefaultTemplateParams object
// with the ability to set a timeout on a request.
func NewGetDefaultTemplateParamsWithTimeout(timeout time.Duration) *GetDefaultTemplateParams {
	return &GetDefaultTemplateParams{
		timeout: timeout,
	}
}

// NewGetDefaultTemplateParamsWithContext creates a new GetDefaultTemplateParams object
// with the ability to set a context for a request.
func NewGetDefaultTemplateParamsWithContext(ctx context.Context) *GetDefaultTemplateParams {
	return &GetDefaultTemplateParams{
		Context: ctx,
	}
}

// NewGetDefaultTemplateParamsWithHTTPClient creates a new GetDefaultTemplateParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetDefaultTemplateParamsWithHTTPClient(client *http.Client) *GetDefaultTemplateParams {
	return &GetDefaultTemplateParams{
		HTTPClient: client,
	}
}

/*
GetDefaultTemplateParams contains all the parameters to send to the API endpoint

	for the get default template operation.

	Typically these are written to a http.Request.
*/
type GetDefaultTemplateParams struct {

	/* FsPath.

	   File system path to the template
	*/
	FsPath string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get default template params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDefaultTemplateParams) WithDefaults() *GetDefaultTemplateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get default template params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetDefaultTemplateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get default template params
func (o *GetDefaultTemplateParams) WithTimeout(timeout time.Duration) *GetDefaultTemplateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get default template params
func (o *GetDefaultTemplateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get default template params
func (o *GetDefaultTemplateParams) WithContext(ctx context.Context) *GetDefaultTemplateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get default template params
func (o *GetDefaultTemplateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get default template params
func (o *GetDefaultTemplateParams) WithHTTPClient(client *http.Client) *GetDefaultTemplateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get default template params
func (o *GetDefaultTemplateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFsPath adds the fsPath to the get default template params
func (o *GetDefaultTemplateParams) WithFsPath(fsPath string) *GetDefaultTemplateParams {
	o.SetFsPath(fsPath)
	return o
}

// SetFsPath adds the fsPath to the get default template params
func (o *GetDefaultTemplateParams) SetFsPath(fsPath string) {
	o.FsPath = fsPath
}

// WithIfMatch adds the ifMatch to the get default template params
func (o *GetDefaultTemplateParams) WithIfMatch(ifMatch *string) *GetDefaultTemplateParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get default template params
func (o *GetDefaultTemplateParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *GetDefaultTemplateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param fsPath
	if err := r.SetPathParam("fsPath", o.FsPath); err != nil {
		return err
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
