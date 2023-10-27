// Code generated by go-swagger; DO NOT EDIT.

package environment

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

// NewGetPublicEnvironmentParams creates a new GetPublicEnvironmentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetPublicEnvironmentParams() *GetPublicEnvironmentParams {
	return &GetPublicEnvironmentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetPublicEnvironmentParamsWithTimeout creates a new GetPublicEnvironmentParams object
// with the ability to set a timeout on a request.
func NewGetPublicEnvironmentParamsWithTimeout(timeout time.Duration) *GetPublicEnvironmentParams {
	return &GetPublicEnvironmentParams{
		timeout: timeout,
	}
}

// NewGetPublicEnvironmentParamsWithContext creates a new GetPublicEnvironmentParams object
// with the ability to set a context for a request.
func NewGetPublicEnvironmentParamsWithContext(ctx context.Context) *GetPublicEnvironmentParams {
	return &GetPublicEnvironmentParams{
		Context: ctx,
	}
}

// NewGetPublicEnvironmentParamsWithHTTPClient creates a new GetPublicEnvironmentParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetPublicEnvironmentParamsWithHTTPClient(client *http.Client) *GetPublicEnvironmentParams {
	return &GetPublicEnvironmentParams{
		HTTPClient: client,
	}
}

/*
GetPublicEnvironmentParams contains all the parameters to send to the API endpoint

	for the get public environment operation.

	Typically these are written to a http.Request.
*/
type GetPublicEnvironmentParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get public environment params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPublicEnvironmentParams) WithDefaults() *GetPublicEnvironmentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get public environment params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPublicEnvironmentParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get public environment params
func (o *GetPublicEnvironmentParams) WithTimeout(timeout time.Duration) *GetPublicEnvironmentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get public environment params
func (o *GetPublicEnvironmentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get public environment params
func (o *GetPublicEnvironmentParams) WithContext(ctx context.Context) *GetPublicEnvironmentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get public environment params
func (o *GetPublicEnvironmentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get public environment params
func (o *GetPublicEnvironmentParams) WithHTTPClient(client *http.Client) *GetPublicEnvironmentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get public environment params
func (o *GetPublicEnvironmentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetPublicEnvironmentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}