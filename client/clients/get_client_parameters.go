// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewGetClientParams creates a new GetClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetClientParams() *GetClientParams {
	return &GetClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetClientParamsWithTimeout creates a new GetClientParams object
// with the ability to set a timeout on a request.
func NewGetClientParamsWithTimeout(timeout time.Duration) *GetClientParams {
	return &GetClientParams{
		timeout: timeout,
	}
}

// NewGetClientParamsWithContext creates a new GetClientParams object
// with the ability to set a context for a request.
func NewGetClientParamsWithContext(ctx context.Context) *GetClientParams {
	return &GetClientParams{
		Context: ctx,
	}
}

// NewGetClientParamsWithHTTPClient creates a new GetClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetClientParamsWithHTTPClient(client *http.Client) *GetClientParams {
	return &GetClientParams{
		HTTPClient: client,
	}
}

/* GetClientParams contains all the parameters to send to the API endpoint
   for the get client operation.

   Typically these are written to a http.Request.
*/
type GetClientParams struct {

	/* Cid.

	   Client id

	   Default: "default"
	*/
	Cid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetClientParams) WithDefaults() *GetClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetClientParams) SetDefaults() {
	var (
		cidDefault = string("default")

		tidDefault = string("default")
	)

	val := GetClientParams{
		Cid: cidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get client params
func (o *GetClientParams) WithTimeout(timeout time.Duration) *GetClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get client params
func (o *GetClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get client params
func (o *GetClientParams) WithContext(ctx context.Context) *GetClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get client params
func (o *GetClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get client params
func (o *GetClientParams) WithHTTPClient(client *http.Client) *GetClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get client params
func (o *GetClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCid adds the cid to the get client params
func (o *GetClientParams) WithCid(cid string) *GetClientParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the get client params
func (o *GetClientParams) SetCid(cid string) {
	o.Cid = cid
}

// WithTid adds the tid to the get client params
func (o *GetClientParams) WithTid(tid string) *GetClientParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get client params
func (o *GetClientParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *GetClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param cid
	if err := r.SetPathParam("cid", o.Cid); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
