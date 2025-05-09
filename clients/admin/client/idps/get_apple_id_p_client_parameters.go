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

// NewGetAppleIDPClientParams creates a new GetAppleIDPClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAppleIDPClientParams() *GetAppleIDPClientParams {
	return &GetAppleIDPClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAppleIDPClientParamsWithTimeout creates a new GetAppleIDPClientParams object
// with the ability to set a timeout on a request.
func NewGetAppleIDPClientParamsWithTimeout(timeout time.Duration) *GetAppleIDPClientParams {
	return &GetAppleIDPClientParams{
		timeout: timeout,
	}
}

// NewGetAppleIDPClientParamsWithContext creates a new GetAppleIDPClientParams object
// with the ability to set a context for a request.
func NewGetAppleIDPClientParamsWithContext(ctx context.Context) *GetAppleIDPClientParams {
	return &GetAppleIDPClientParams{
		Context: ctx,
	}
}

// NewGetAppleIDPClientParamsWithHTTPClient creates a new GetAppleIDPClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAppleIDPClientParamsWithHTTPClient(client *http.Client) *GetAppleIDPClientParams {
	return &GetAppleIDPClientParams{
		HTTPClient: client,
	}
}

/*
GetAppleIDPClientParams contains all the parameters to send to the API endpoint

	for the get apple ID p client operation.

	Typically these are written to a http.Request.
*/
type GetAppleIDPClientParams struct {

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

// WithDefaults hydrates default values in the get apple ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAppleIDPClientParams) WithDefaults() *GetAppleIDPClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get apple ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAppleIDPClientParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetAppleIDPClientParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get apple ID p client params
func (o *GetAppleIDPClientParams) WithTimeout(timeout time.Duration) *GetAppleIDPClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get apple ID p client params
func (o *GetAppleIDPClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get apple ID p client params
func (o *GetAppleIDPClientParams) WithContext(ctx context.Context) *GetAppleIDPClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get apple ID p client params
func (o *GetAppleIDPClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get apple ID p client params
func (o *GetAppleIDPClientParams) WithHTTPClient(client *http.Client) *GetAppleIDPClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get apple ID p client params
func (o *GetAppleIDPClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get apple ID p client params
func (o *GetAppleIDPClientParams) WithIfMatch(ifMatch *string) *GetAppleIDPClientParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get apple ID p client params
func (o *GetAppleIDPClientParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get apple ID p client params
func (o *GetAppleIDPClientParams) WithIid(iid string) *GetAppleIDPClientParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get apple ID p client params
func (o *GetAppleIDPClientParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get apple ID p client params
func (o *GetAppleIDPClientParams) WithWid(wid string) *GetAppleIDPClientParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get apple ID p client params
func (o *GetAppleIDPClientParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetAppleIDPClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
