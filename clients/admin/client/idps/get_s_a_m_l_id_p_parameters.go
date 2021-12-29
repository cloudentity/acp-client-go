// Code generated by go-swagger; DO NOT EDIT.

package idps

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

// NewGetSAMLIDPParams creates a new GetSAMLIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetSAMLIDPParams() *GetSAMLIDPParams {
	return &GetSAMLIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetSAMLIDPParamsWithTimeout creates a new GetSAMLIDPParams object
// with the ability to set a timeout on a request.
func NewGetSAMLIDPParamsWithTimeout(timeout time.Duration) *GetSAMLIDPParams {
	return &GetSAMLIDPParams{
		timeout: timeout,
	}
}

// NewGetSAMLIDPParamsWithContext creates a new GetSAMLIDPParams object
// with the ability to set a context for a request.
func NewGetSAMLIDPParamsWithContext(ctx context.Context) *GetSAMLIDPParams {
	return &GetSAMLIDPParams{
		Context: ctx,
	}
}

// NewGetSAMLIDPParamsWithHTTPClient creates a new GetSAMLIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetSAMLIDPParamsWithHTTPClient(client *http.Client) *GetSAMLIDPParams {
	return &GetSAMLIDPParams{
		HTTPClient: client,
	}
}

/* GetSAMLIDPParams contains all the parameters to send to the API endpoint
   for the get s a m l ID p operation.

   Typically these are written to a http.Request.
*/
type GetSAMLIDPParams struct {

	/* Iid.

	   IDP id
	*/
	Iid string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get s a m l ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetSAMLIDPParams) WithDefaults() *GetSAMLIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get s a m l ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetSAMLIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetSAMLIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithTimeout(timeout time.Duration) *GetSAMLIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithContext(ctx context.Context) *GetSAMLIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithHTTPClient(client *http.Client) *GetSAMLIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIid adds the iid to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithIid(iid string) *GetSAMLIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithWid(wid string) *GetSAMLIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetSAMLIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param iid
	if err := r.SetPathParam("iid", o.Iid); err != nil {
		return err
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
