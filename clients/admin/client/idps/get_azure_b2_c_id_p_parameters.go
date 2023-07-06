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

// NewGetAzureB2CIDPParams creates a new GetAzureB2CIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAzureB2CIDPParams() *GetAzureB2CIDPParams {
	return &GetAzureB2CIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAzureB2CIDPParamsWithTimeout creates a new GetAzureB2CIDPParams object
// with the ability to set a timeout on a request.
func NewGetAzureB2CIDPParamsWithTimeout(timeout time.Duration) *GetAzureB2CIDPParams {
	return &GetAzureB2CIDPParams{
		timeout: timeout,
	}
}

// NewGetAzureB2CIDPParamsWithContext creates a new GetAzureB2CIDPParams object
// with the ability to set a context for a request.
func NewGetAzureB2CIDPParamsWithContext(ctx context.Context) *GetAzureB2CIDPParams {
	return &GetAzureB2CIDPParams{
		Context: ctx,
	}
}

// NewGetAzureB2CIDPParamsWithHTTPClient creates a new GetAzureB2CIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAzureB2CIDPParamsWithHTTPClient(client *http.Client) *GetAzureB2CIDPParams {
	return &GetAzureB2CIDPParams{
		HTTPClient: client,
	}
}

/*
GetAzureB2CIDPParams contains all the parameters to send to the API endpoint

	for the get azure b2 c ID p operation.

	Typically these are written to a http.Request.
*/
type GetAzureB2CIDPParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

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

// WithDefaults hydrates default values in the get azure b2 c ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAzureB2CIDPParams) WithDefaults() *GetAzureB2CIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get azure b2 c ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAzureB2CIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetAzureB2CIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) WithTimeout(timeout time.Duration) *GetAzureB2CIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) WithContext(ctx context.Context) *GetAzureB2CIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) WithHTTPClient(client *http.Client) *GetAzureB2CIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) WithIfMatch(ifMatch *string) *GetAzureB2CIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) WithIid(iid string) *GetAzureB2CIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) WithWid(wid string) *GetAzureB2CIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get azure b2 c ID p params
func (o *GetAzureB2CIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetAzureB2CIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
