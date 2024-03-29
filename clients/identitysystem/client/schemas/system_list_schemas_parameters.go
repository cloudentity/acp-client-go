// Code generated by go-swagger; DO NOT EDIT.

package schemas

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

// NewSystemListSchemasParams creates a new SystemListSchemasParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSystemListSchemasParams() *SystemListSchemasParams {
	return &SystemListSchemasParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSystemListSchemasParamsWithTimeout creates a new SystemListSchemasParams object
// with the ability to set a timeout on a request.
func NewSystemListSchemasParamsWithTimeout(timeout time.Duration) *SystemListSchemasParams {
	return &SystemListSchemasParams{
		timeout: timeout,
	}
}

// NewSystemListSchemasParamsWithContext creates a new SystemListSchemasParams object
// with the ability to set a context for a request.
func NewSystemListSchemasParamsWithContext(ctx context.Context) *SystemListSchemasParams {
	return &SystemListSchemasParams{
		Context: ctx,
	}
}

// NewSystemListSchemasParamsWithHTTPClient creates a new SystemListSchemasParams object
// with the ability to set a custom HTTPClient for a request.
func NewSystemListSchemasParamsWithHTTPClient(client *http.Client) *SystemListSchemasParams {
	return &SystemListSchemasParams{
		HTTPClient: client,
	}
}

/*
SystemListSchemasParams contains all the parameters to send to the API endpoint

	for the system list schemas operation.

	Typically these are written to a http.Request.
*/
type SystemListSchemasParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the system list schemas params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemListSchemasParams) WithDefaults() *SystemListSchemasParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the system list schemas params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemListSchemasParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the system list schemas params
func (o *SystemListSchemasParams) WithTimeout(timeout time.Duration) *SystemListSchemasParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the system list schemas params
func (o *SystemListSchemasParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the system list schemas params
func (o *SystemListSchemasParams) WithContext(ctx context.Context) *SystemListSchemasParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the system list schemas params
func (o *SystemListSchemasParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the system list schemas params
func (o *SystemListSchemasParams) WithHTTPClient(client *http.Client) *SystemListSchemasParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the system list schemas params
func (o *SystemListSchemasParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the system list schemas params
func (o *SystemListSchemasParams) WithIfMatch(ifMatch *string) *SystemListSchemasParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the system list schemas params
func (o *SystemListSchemasParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *SystemListSchemasParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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
