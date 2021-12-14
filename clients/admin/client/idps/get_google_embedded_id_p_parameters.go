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

// NewGetGoogleEmbeddedIDPParams creates a new GetGoogleEmbeddedIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetGoogleEmbeddedIDPParams() *GetGoogleEmbeddedIDPParams {
	return &GetGoogleEmbeddedIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetGoogleEmbeddedIDPParamsWithTimeout creates a new GetGoogleEmbeddedIDPParams object
// with the ability to set a timeout on a request.
func NewGetGoogleEmbeddedIDPParamsWithTimeout(timeout time.Duration) *GetGoogleEmbeddedIDPParams {
	return &GetGoogleEmbeddedIDPParams{
		timeout: timeout,
	}
}

// NewGetGoogleEmbeddedIDPParamsWithContext creates a new GetGoogleEmbeddedIDPParams object
// with the ability to set a context for a request.
func NewGetGoogleEmbeddedIDPParamsWithContext(ctx context.Context) *GetGoogleEmbeddedIDPParams {
	return &GetGoogleEmbeddedIDPParams{
		Context: ctx,
	}
}

// NewGetGoogleEmbeddedIDPParamsWithHTTPClient creates a new GetGoogleEmbeddedIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetGoogleEmbeddedIDPParamsWithHTTPClient(client *http.Client) *GetGoogleEmbeddedIDPParams {
	return &GetGoogleEmbeddedIDPParams{
		HTTPClient: client,
	}
}

/* GetGoogleEmbeddedIDPParams contains all the parameters to send to the API endpoint
   for the get google embedded ID p operation.

   Typically these are written to a http.Request.
*/
type GetGoogleEmbeddedIDPParams struct {

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

// WithDefaults hydrates default values in the get google embedded ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetGoogleEmbeddedIDPParams) WithDefaults() *GetGoogleEmbeddedIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get google embedded ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetGoogleEmbeddedIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetGoogleEmbeddedIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) WithTimeout(timeout time.Duration) *GetGoogleEmbeddedIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) WithContext(ctx context.Context) *GetGoogleEmbeddedIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) WithHTTPClient(client *http.Client) *GetGoogleEmbeddedIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIid adds the iid to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) WithIid(iid string) *GetGoogleEmbeddedIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) WithWid(wid string) *GetGoogleEmbeddedIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get google embedded ID p params
func (o *GetGoogleEmbeddedIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetGoogleEmbeddedIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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