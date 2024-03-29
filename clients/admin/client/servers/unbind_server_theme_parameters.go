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

// NewUnbindServerThemeParams creates a new UnbindServerThemeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUnbindServerThemeParams() *UnbindServerThemeParams {
	return &UnbindServerThemeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUnbindServerThemeParamsWithTimeout creates a new UnbindServerThemeParams object
// with the ability to set a timeout on a request.
func NewUnbindServerThemeParamsWithTimeout(timeout time.Duration) *UnbindServerThemeParams {
	return &UnbindServerThemeParams{
		timeout: timeout,
	}
}

// NewUnbindServerThemeParamsWithContext creates a new UnbindServerThemeParams object
// with the ability to set a context for a request.
func NewUnbindServerThemeParamsWithContext(ctx context.Context) *UnbindServerThemeParams {
	return &UnbindServerThemeParams{
		Context: ctx,
	}
}

// NewUnbindServerThemeParamsWithHTTPClient creates a new UnbindServerThemeParams object
// with the ability to set a custom HTTPClient for a request.
func NewUnbindServerThemeParamsWithHTTPClient(client *http.Client) *UnbindServerThemeParams {
	return &UnbindServerThemeParams{
		HTTPClient: client,
	}
}

/*
UnbindServerThemeParams contains all the parameters to send to the API endpoint

	for the unbind server theme operation.

	Typically these are written to a http.Request.
*/
type UnbindServerThemeParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the unbind server theme params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UnbindServerThemeParams) WithDefaults() *UnbindServerThemeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the unbind server theme params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UnbindServerThemeParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := UnbindServerThemeParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the unbind server theme params
func (o *UnbindServerThemeParams) WithTimeout(timeout time.Duration) *UnbindServerThemeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the unbind server theme params
func (o *UnbindServerThemeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the unbind server theme params
func (o *UnbindServerThemeParams) WithContext(ctx context.Context) *UnbindServerThemeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the unbind server theme params
func (o *UnbindServerThemeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the unbind server theme params
func (o *UnbindServerThemeParams) WithHTTPClient(client *http.Client) *UnbindServerThemeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the unbind server theme params
func (o *UnbindServerThemeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the unbind server theme params
func (o *UnbindServerThemeParams) WithIfMatch(ifMatch *string) *UnbindServerThemeParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the unbind server theme params
func (o *UnbindServerThemeParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the unbind server theme params
func (o *UnbindServerThemeParams) WithWid(wid string) *UnbindServerThemeParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the unbind server theme params
func (o *UnbindServerThemeParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UnbindServerThemeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
