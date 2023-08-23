// Code generated by go-swagger; DO NOT EDIT.

package d_c_r

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

// NewFDXDynamicClientRegistrationDeleteParams creates a new FDXDynamicClientRegistrationDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewFDXDynamicClientRegistrationDeleteParams() *FDXDynamicClientRegistrationDeleteParams {
	return &FDXDynamicClientRegistrationDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewFDXDynamicClientRegistrationDeleteParamsWithTimeout creates a new FDXDynamicClientRegistrationDeleteParams object
// with the ability to set a timeout on a request.
func NewFDXDynamicClientRegistrationDeleteParamsWithTimeout(timeout time.Duration) *FDXDynamicClientRegistrationDeleteParams {
	return &FDXDynamicClientRegistrationDeleteParams{
		timeout: timeout,
	}
}

// NewFDXDynamicClientRegistrationDeleteParamsWithContext creates a new FDXDynamicClientRegistrationDeleteParams object
// with the ability to set a context for a request.
func NewFDXDynamicClientRegistrationDeleteParamsWithContext(ctx context.Context) *FDXDynamicClientRegistrationDeleteParams {
	return &FDXDynamicClientRegistrationDeleteParams{
		Context: ctx,
	}
}

// NewFDXDynamicClientRegistrationDeleteParamsWithHTTPClient creates a new FDXDynamicClientRegistrationDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewFDXDynamicClientRegistrationDeleteParamsWithHTTPClient(client *http.Client) *FDXDynamicClientRegistrationDeleteParams {
	return &FDXDynamicClientRegistrationDeleteParams{
		HTTPClient: client,
	}
}

/*
FDXDynamicClientRegistrationDeleteParams contains all the parameters to send to the API endpoint

	for the f d x dynamic client registration delete operation.

	Typically these are written to a http.Request.
*/
type FDXDynamicClientRegistrationDeleteParams struct {

	/* Cid.

	   Client id

	   Default: "default"
	*/
	Cid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the f d x dynamic client registration delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FDXDynamicClientRegistrationDeleteParams) WithDefaults() *FDXDynamicClientRegistrationDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the f d x dynamic client registration delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FDXDynamicClientRegistrationDeleteParams) SetDefaults() {
	var (
		cidDefault = string("default")
	)

	val := FDXDynamicClientRegistrationDeleteParams{
		Cid: cidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) WithTimeout(timeout time.Duration) *FDXDynamicClientRegistrationDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) WithContext(ctx context.Context) *FDXDynamicClientRegistrationDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) WithHTTPClient(client *http.Client) *FDXDynamicClientRegistrationDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCid adds the cid to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) WithCid(cid string) *FDXDynamicClientRegistrationDeleteParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the f d x dynamic client registration delete params
func (o *FDXDynamicClientRegistrationDeleteParams) SetCid(cid string) {
	o.Cid = cid
}

// WriteToRequest writes these params to a swagger request
func (o *FDXDynamicClientRegistrationDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param cid
	if err := r.SetPathParam("cid", o.Cid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}