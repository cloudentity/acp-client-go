// Code generated by go-swagger; DO NOT EDIT.

package servers

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

// NewGetCIBAAuthenticationServiceParams creates a new GetCIBAAuthenticationServiceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCIBAAuthenticationServiceParams() *GetCIBAAuthenticationServiceParams {
	return &GetCIBAAuthenticationServiceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCIBAAuthenticationServiceParamsWithTimeout creates a new GetCIBAAuthenticationServiceParams object
// with the ability to set a timeout on a request.
func NewGetCIBAAuthenticationServiceParamsWithTimeout(timeout time.Duration) *GetCIBAAuthenticationServiceParams {
	return &GetCIBAAuthenticationServiceParams{
		timeout: timeout,
	}
}

// NewGetCIBAAuthenticationServiceParamsWithContext creates a new GetCIBAAuthenticationServiceParams object
// with the ability to set a context for a request.
func NewGetCIBAAuthenticationServiceParamsWithContext(ctx context.Context) *GetCIBAAuthenticationServiceParams {
	return &GetCIBAAuthenticationServiceParams{
		Context: ctx,
	}
}

// NewGetCIBAAuthenticationServiceParamsWithHTTPClient creates a new GetCIBAAuthenticationServiceParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCIBAAuthenticationServiceParamsWithHTTPClient(client *http.Client) *GetCIBAAuthenticationServiceParams {
	return &GetCIBAAuthenticationServiceParams{
		HTTPClient: client,
	}
}

/*
GetCIBAAuthenticationServiceParams contains all the parameters to send to the API endpoint

	for the get c i b a authentication service operation.

	Typically these are written to a http.Request.
*/
type GetCIBAAuthenticationServiceParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get c i b a authentication service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCIBAAuthenticationServiceParams) WithDefaults() *GetCIBAAuthenticationServiceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get c i b a authentication service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCIBAAuthenticationServiceParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetCIBAAuthenticationServiceParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) WithTimeout(timeout time.Duration) *GetCIBAAuthenticationServiceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) WithContext(ctx context.Context) *GetCIBAAuthenticationServiceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) WithHTTPClient(client *http.Client) *GetCIBAAuthenticationServiceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) WithIfMatch(ifMatch *string) *GetCIBAAuthenticationServiceParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) WithWid(wid string) *GetCIBAAuthenticationServiceParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get c i b a authentication service params
func (o *GetCIBAAuthenticationServiceParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetCIBAAuthenticationServiceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
