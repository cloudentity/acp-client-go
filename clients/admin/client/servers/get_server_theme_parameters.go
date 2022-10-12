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

// NewGetServerThemeParams creates a new GetServerThemeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetServerThemeParams() *GetServerThemeParams {
	return &GetServerThemeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetServerThemeParamsWithTimeout creates a new GetServerThemeParams object
// with the ability to set a timeout on a request.
func NewGetServerThemeParamsWithTimeout(timeout time.Duration) *GetServerThemeParams {
	return &GetServerThemeParams{
		timeout: timeout,
	}
}

// NewGetServerThemeParamsWithContext creates a new GetServerThemeParams object
// with the ability to set a context for a request.
func NewGetServerThemeParamsWithContext(ctx context.Context) *GetServerThemeParams {
	return &GetServerThemeParams{
		Context: ctx,
	}
}

// NewGetServerThemeParamsWithHTTPClient creates a new GetServerThemeParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetServerThemeParamsWithHTTPClient(client *http.Client) *GetServerThemeParams {
	return &GetServerThemeParams{
		HTTPClient: client,
	}
}

/*
GetServerThemeParams contains all the parameters to send to the API endpoint

	for the get server theme operation.

	Typically these are written to a http.Request.
*/
type GetServerThemeParams struct {

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get server theme params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetServerThemeParams) WithDefaults() *GetServerThemeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get server theme params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetServerThemeParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetServerThemeParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get server theme params
func (o *GetServerThemeParams) WithTimeout(timeout time.Duration) *GetServerThemeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get server theme params
func (o *GetServerThemeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get server theme params
func (o *GetServerThemeParams) WithContext(ctx context.Context) *GetServerThemeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get server theme params
func (o *GetServerThemeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get server theme params
func (o *GetServerThemeParams) WithHTTPClient(client *http.Client) *GetServerThemeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get server theme params
func (o *GetServerThemeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithWid adds the wid to the get server theme params
func (o *GetServerThemeParams) WithWid(wid string) *GetServerThemeParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get server theme params
func (o *GetServerThemeParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetServerThemeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
