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

// NewGetAzureIDPClientParams creates a new GetAzureIDPClientParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAzureIDPClientParams() *GetAzureIDPClientParams {
	return &GetAzureIDPClientParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAzureIDPClientParamsWithTimeout creates a new GetAzureIDPClientParams object
// with the ability to set a timeout on a request.
func NewGetAzureIDPClientParamsWithTimeout(timeout time.Duration) *GetAzureIDPClientParams {
	return &GetAzureIDPClientParams{
		timeout: timeout,
	}
}

// NewGetAzureIDPClientParamsWithContext creates a new GetAzureIDPClientParams object
// with the ability to set a context for a request.
func NewGetAzureIDPClientParamsWithContext(ctx context.Context) *GetAzureIDPClientParams {
	return &GetAzureIDPClientParams{
		Context: ctx,
	}
}

// NewGetAzureIDPClientParamsWithHTTPClient creates a new GetAzureIDPClientParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAzureIDPClientParamsWithHTTPClient(client *http.Client) *GetAzureIDPClientParams {
	return &GetAzureIDPClientParams{
		HTTPClient: client,
	}
}

/*
GetAzureIDPClientParams contains all the parameters to send to the API endpoint

	for the get azure ID p client operation.

	Typically these are written to a http.Request.
*/
type GetAzureIDPClientParams struct {

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

// WithDefaults hydrates default values in the get azure ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAzureIDPClientParams) WithDefaults() *GetAzureIDPClientParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get azure ID p client params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAzureIDPClientParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetAzureIDPClientParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get azure ID p client params
func (o *GetAzureIDPClientParams) WithTimeout(timeout time.Duration) *GetAzureIDPClientParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get azure ID p client params
func (o *GetAzureIDPClientParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get azure ID p client params
func (o *GetAzureIDPClientParams) WithContext(ctx context.Context) *GetAzureIDPClientParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get azure ID p client params
func (o *GetAzureIDPClientParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get azure ID p client params
func (o *GetAzureIDPClientParams) WithHTTPClient(client *http.Client) *GetAzureIDPClientParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get azure ID p client params
func (o *GetAzureIDPClientParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get azure ID p client params
func (o *GetAzureIDPClientParams) WithIfMatch(ifMatch *string) *GetAzureIDPClientParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get azure ID p client params
func (o *GetAzureIDPClientParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get azure ID p client params
func (o *GetAzureIDPClientParams) WithIid(iid string) *GetAzureIDPClientParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get azure ID p client params
func (o *GetAzureIDPClientParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get azure ID p client params
func (o *GetAzureIDPClientParams) WithWid(wid string) *GetAzureIDPClientParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get azure ID p client params
func (o *GetAzureIDPClientParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetAzureIDPClientParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
