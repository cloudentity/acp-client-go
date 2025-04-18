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

// NewGetXIDPClientParams creates a new GetXIDPClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetXIDPClientParams() *GetXIDPClientParams {
	return &GetXIDPClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetXIDPClientParamsWithTimeout creates a new GetXIDPClientParams object
// with the ability to set a timeout on a request.
func NewGetXIDPClientParamsWithTimeout(timeout time.Duration) *GetXIDPClientParams {
	return &GetXIDPClientParams{
		timeout: timeout,
	}
}

// NewGetXIDPClientParamsWithContext creates a new GetXIDPClientParams object
// with the ability to set a context for a request.
func NewGetXIDPClientParamsWithContext(ctx context.Context) *GetXIDPClientParams {
	return &GetXIDPClientParams{
		Context: ctx,
	}
}

// NewGetXIDPClientParamsWithHTTPClient creates a new GetXIDPClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetXIDPClientParamsWithHTTPClient(client *http.Client) *GetXIDPClientParams {
	return &GetXIDPClientParams{
		HTTPClient: client,
	}
}

/*
GetXIDPClientParams contains all the parameters to send to the API endpoint

	for the get x ID p client operation.

	Typically these are written to a http.Request.
*/
type GetXIDPClientParams struct {

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

// WithDefaults hydrates default values in the get x ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetXIDPClientParams) WithDefaults() *GetXIDPClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get x ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetXIDPClientParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetXIDPClientParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get x ID p client params
func (o *GetXIDPClientParams) WithTimeout(timeout time.Duration) *GetXIDPClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get x ID p client params
func (o *GetXIDPClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get x ID p client params
func (o *GetXIDPClientParams) WithContext(ctx context.Context) *GetXIDPClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get x ID p client params
func (o *GetXIDPClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get x ID p client params
func (o *GetXIDPClientParams) WithHTTPClient(client *http.Client) *GetXIDPClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get x ID p client params
func (o *GetXIDPClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get x ID p client params
func (o *GetXIDPClientParams) WithIfMatch(ifMatch *string) *GetXIDPClientParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get x ID p client params
func (o *GetXIDPClientParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get x ID p client params
func (o *GetXIDPClientParams) WithIid(iid string) *GetXIDPClientParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get x ID p client params
func (o *GetXIDPClientParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get x ID p client params
func (o *GetXIDPClientParams) WithWid(wid string) *GetXIDPClientParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get x ID p client params
func (o *GetXIDPClientParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetXIDPClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
