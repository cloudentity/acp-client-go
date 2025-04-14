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

// NewGetLinkedInIDPClientParams creates a new GetLinkedInIDPClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetLinkedInIDPClientParams() *GetLinkedInIDPClientParams {
	return &GetLinkedInIDPClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetLinkedInIDPClientParamsWithTimeout creates a new GetLinkedInIDPClientParams object
// with the ability to set a timeout on a request.
func NewGetLinkedInIDPClientParamsWithTimeout(timeout time.Duration) *GetLinkedInIDPClientParams {
	return &GetLinkedInIDPClientParams{
		timeout: timeout,
	}
}

// NewGetLinkedInIDPClientParamsWithContext creates a new GetLinkedInIDPClientParams object
// with the ability to set a context for a request.
func NewGetLinkedInIDPClientParamsWithContext(ctx context.Context) *GetLinkedInIDPClientParams {
	return &GetLinkedInIDPClientParams{
		Context: ctx,
	}
}

// NewGetLinkedInIDPClientParamsWithHTTPClient creates a new GetLinkedInIDPClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetLinkedInIDPClientParamsWithHTTPClient(client *http.Client) *GetLinkedInIDPClientParams {
	return &GetLinkedInIDPClientParams{
		HTTPClient: client,
	}
}

/*
GetLinkedInIDPClientParams contains all the parameters to send to the API endpoint

	for the get linked in ID p client operation.

	Typically these are written to a http.Request.
*/
type GetLinkedInIDPClientParams struct {

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

// WithDefaults hydrates default values in the get linked in ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetLinkedInIDPClientParams) WithDefaults() *GetLinkedInIDPClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get linked in ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetLinkedInIDPClientParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetLinkedInIDPClientParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) WithTimeout(timeout time.Duration) *GetLinkedInIDPClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) WithContext(ctx context.Context) *GetLinkedInIDPClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) WithHTTPClient(client *http.Client) *GetLinkedInIDPClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) WithIfMatch(ifMatch *string) *GetLinkedInIDPClientParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) WithIid(iid string) *GetLinkedInIDPClientParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) WithWid(wid string) *GetLinkedInIDPClientParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get linked in ID p client params
func (o *GetLinkedInIDPClientParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetLinkedInIDPClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
