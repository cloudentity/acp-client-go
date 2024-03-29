// Code generated by go-swagger; DO NOT EDIT.

package tenants

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

// NewGetTenantParams creates a new GetTenantParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetTenantParams() *GetTenantParams {
	return &GetTenantParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetTenantParamsWithTimeout creates a new GetTenantParams object
// with the ability to set a timeout on a request.
func NewGetTenantParamsWithTimeout(timeout time.Duration) *GetTenantParams {
	return &GetTenantParams{
		timeout: timeout,
	}
}

// NewGetTenantParamsWithContext creates a new GetTenantParams object
// with the ability to set a context for a request.
func NewGetTenantParamsWithContext(ctx context.Context) *GetTenantParams {
	return &GetTenantParams{
		Context: ctx,
	}
}

// NewGetTenantParamsWithHTTPClient creates a new GetTenantParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetTenantParamsWithHTTPClient(client *http.Client) *GetTenantParams {
	return &GetTenantParams{
		HTTPClient: client,
	}
}

/*
GetTenantParams contains all the parameters to send to the API endpoint

	for the get tenant operation.

	Typically these are written to a http.Request.
*/
type GetTenantParams struct {

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get tenant params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTenantParams) WithDefaults() *GetTenantParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get tenant params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetTenantParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := GetTenantParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get tenant params
func (o *GetTenantParams) WithTimeout(timeout time.Duration) *GetTenantParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get tenant params
func (o *GetTenantParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get tenant params
func (o *GetTenantParams) WithContext(ctx context.Context) *GetTenantParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get tenant params
func (o *GetTenantParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get tenant params
func (o *GetTenantParams) WithHTTPClient(client *http.Client) *GetTenantParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get tenant params
func (o *GetTenantParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTid adds the tid to the get tenant params
func (o *GetTenantParams) WithTid(tid string) *GetTenantParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get tenant params
func (o *GetTenantParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *GetTenantParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
