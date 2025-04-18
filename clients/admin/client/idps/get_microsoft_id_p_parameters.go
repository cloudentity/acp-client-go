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

// NewGetMicrosoftIDPParams creates a new GetMicrosoftIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetMicrosoftIDPParams() *GetMicrosoftIDPParams {
	return &GetMicrosoftIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetMicrosoftIDPParamsWithTimeout creates a new GetMicrosoftIDPParams object
// with the ability to set a timeout on a request.
func NewGetMicrosoftIDPParamsWithTimeout(timeout time.Duration) *GetMicrosoftIDPParams {
	return &GetMicrosoftIDPParams{
		timeout: timeout,
	}
}

// NewGetMicrosoftIDPParamsWithContext creates a new GetMicrosoftIDPParams object
// with the ability to set a context for a request.
func NewGetMicrosoftIDPParamsWithContext(ctx context.Context) *GetMicrosoftIDPParams {
	return &GetMicrosoftIDPParams{
		Context: ctx,
	}
}

// NewGetMicrosoftIDPParamsWithHTTPClient creates a new GetMicrosoftIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetMicrosoftIDPParamsWithHTTPClient(client *http.Client) *GetMicrosoftIDPParams {
	return &GetMicrosoftIDPParams{
		HTTPClient: client,
	}
}

/*
GetMicrosoftIDPParams contains all the parameters to send to the API endpoint

	for the get microsoft ID p operation.

	Typically these are written to a http.Request.
*/
type GetMicrosoftIDPParams struct {

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

// WithDefaults hydrates default values in the get microsoft ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetMicrosoftIDPParams) WithDefaults() *GetMicrosoftIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get microsoft ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetMicrosoftIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetMicrosoftIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) WithTimeout(timeout time.Duration) *GetMicrosoftIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) WithContext(ctx context.Context) *GetMicrosoftIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) WithHTTPClient(client *http.Client) *GetMicrosoftIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) WithIfMatch(ifMatch *string) *GetMicrosoftIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) WithIid(iid string) *GetMicrosoftIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) WithWid(wid string) *GetMicrosoftIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get microsoft ID p params
func (o *GetMicrosoftIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetMicrosoftIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
