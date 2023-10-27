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

// NewGetIdentityPoolIDPClientParams creates a new GetIdentityPoolIDPClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetIdentityPoolIDPClientParams() *GetIdentityPoolIDPClientParams {
	return &GetIdentityPoolIDPClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetIdentityPoolIDPClientParamsWithTimeout creates a new GetIdentityPoolIDPClientParams object
// with the ability to set a timeout on a request.
func NewGetIdentityPoolIDPClientParamsWithTimeout(timeout time.Duration) *GetIdentityPoolIDPClientParams {
	return &GetIdentityPoolIDPClientParams{
		timeout: timeout,
	}
}

// NewGetIdentityPoolIDPClientParamsWithContext creates a new GetIdentityPoolIDPClientParams object
// with the ability to set a context for a request.
func NewGetIdentityPoolIDPClientParamsWithContext(ctx context.Context) *GetIdentityPoolIDPClientParams {
	return &GetIdentityPoolIDPClientParams{
		Context: ctx,
	}
}

// NewGetIdentityPoolIDPClientParamsWithHTTPClient creates a new GetIdentityPoolIDPClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetIdentityPoolIDPClientParamsWithHTTPClient(client *http.Client) *GetIdentityPoolIDPClientParams {
	return &GetIdentityPoolIDPClientParams{
		HTTPClient: client,
	}
}

/*
GetIdentityPoolIDPClientParams contains all the parameters to send to the API endpoint

	for the get identity pool ID p client operation.

	Typically these are written to a http.Request.
*/
type GetIdentityPoolIDPClientParams struct {

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

// WithDefaults hydrates default values in the get identity pool ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetIdentityPoolIDPClientParams) WithDefaults() *GetIdentityPoolIDPClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get identity pool ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetIdentityPoolIDPClientParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetIdentityPoolIDPClientParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) WithTimeout(timeout time.Duration) *GetIdentityPoolIDPClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) WithContext(ctx context.Context) *GetIdentityPoolIDPClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) WithHTTPClient(client *http.Client) *GetIdentityPoolIDPClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) WithIfMatch(ifMatch *string) *GetIdentityPoolIDPClientParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) WithIid(iid string) *GetIdentityPoolIDPClientParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) WithWid(wid string) *GetIdentityPoolIDPClientParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get identity pool ID p client params
func (o *GetIdentityPoolIDPClientParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetIdentityPoolIDPClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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