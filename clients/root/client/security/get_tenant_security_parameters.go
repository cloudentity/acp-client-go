// Code generated by go-swagger; DO NOT EDIT.

package security

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

// NewGetTenantSecurityParams creates a new GetTenantSecurityParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetTenantSecurityParams() *GetTenantSecurityParams {
	return &GetTenantSecurityParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetTenantSecurityParamsWithTimeout creates a new GetTenantSecurityParams object
// with the ability to set a timeout on a request.
func NewGetTenantSecurityParamsWithTimeout(timeout time.Duration) *GetTenantSecurityParams {
	return &GetTenantSecurityParams{
		timeout: timeout,
	}
}

// NewGetTenantSecurityParamsWithContext creates a new GetTenantSecurityParams object
// with the ability to set a context for a request.
func NewGetTenantSecurityParamsWithContext(ctx context.Context) *GetTenantSecurityParams {
	return &GetTenantSecurityParams{
		Context: ctx,
	}
}

// NewGetTenantSecurityParamsWithHTTPClient creates a new GetTenantSecurityParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetTenantSecurityParamsWithHTTPClient(client *http.Client) *GetTenantSecurityParams {
	return &GetTenantSecurityParams{
		HTTPClient: client,
	}
}

/*
GetTenantSecurityParams contains all the parameters to send to the API endpoint

	for the get tenant security operation.

	Typically these are written to a http.Request.
*/
type GetTenantSecurityParams struct {

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get tenant security params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTenantSecurityParams) WithDefaults() *GetTenantSecurityParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get tenant security params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTenantSecurityParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := GetTenantSecurityParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get tenant security params
func (o *GetTenantSecurityParams) WithTimeout(timeout time.Duration) *GetTenantSecurityParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get tenant security params
func (o *GetTenantSecurityParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get tenant security params
func (o *GetTenantSecurityParams) WithContext(ctx context.Context) *GetTenantSecurityParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get tenant security params
func (o *GetTenantSecurityParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get tenant security params
func (o *GetTenantSecurityParams) WithHTTPClient(client *http.Client) *GetTenantSecurityParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get tenant security params
func (o *GetTenantSecurityParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTid adds the tid to the get tenant security params
func (o *GetTenantSecurityParams) WithTid(tid string) *GetTenantSecurityParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get tenant security params
func (o *GetTenantSecurityParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *GetTenantSecurityParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}