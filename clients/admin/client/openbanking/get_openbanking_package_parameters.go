// Code generated by go-swagger; DO NOT EDIT.

package openbanking

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

// NewGetOpenbankingPackageParams creates a new GetOpenbankingPackageParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetOpenbankingPackageParams() *GetOpenbankingPackageParams {
	return &GetOpenbankingPackageParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetOpenbankingPackageParamsWithTimeout creates a new GetOpenbankingPackageParams object
// with the ability to set a timeout on a request.
func NewGetOpenbankingPackageParamsWithTimeout(timeout time.Duration) *GetOpenbankingPackageParams {
	return &GetOpenbankingPackageParams{
		timeout: timeout,
	}
}

// NewGetOpenbankingPackageParamsWithContext creates a new GetOpenbankingPackageParams object
// with the ability to set a context for a request.
func NewGetOpenbankingPackageParamsWithContext(ctx context.Context) *GetOpenbankingPackageParams {
	return &GetOpenbankingPackageParams{
		Context: ctx,
	}
}

// NewGetOpenbankingPackageParamsWithHTTPClient creates a new GetOpenbankingPackageParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetOpenbankingPackageParamsWithHTTPClient(client *http.Client) *GetOpenbankingPackageParams {
	return &GetOpenbankingPackageParams{
		HTTPClient: client,
	}
}

/*
GetOpenbankingPackageParams contains all the parameters to send to the API endpoint

	for the get openbanking package operation.

	Typically these are written to a http.Request.
*/
type GetOpenbankingPackageParams struct {

	/* Wid.

	   ID of your authorization server (workspace)

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get openbanking package params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOpenbankingPackageParams) WithDefaults() *GetOpenbankingPackageParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get openbanking package params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOpenbankingPackageParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetOpenbankingPackageParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get openbanking package params
func (o *GetOpenbankingPackageParams) WithTimeout(timeout time.Duration) *GetOpenbankingPackageParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get openbanking package params
func (o *GetOpenbankingPackageParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get openbanking package params
func (o *GetOpenbankingPackageParams) WithContext(ctx context.Context) *GetOpenbankingPackageParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get openbanking package params
func (o *GetOpenbankingPackageParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get openbanking package params
func (o *GetOpenbankingPackageParams) WithHTTPClient(client *http.Client) *GetOpenbankingPackageParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get openbanking package params
func (o *GetOpenbankingPackageParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithWid adds the wid to the get openbanking package params
func (o *GetOpenbankingPackageParams) WithWid(wid string) *GetOpenbankingPackageParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get openbanking package params
func (o *GetOpenbankingPackageParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetOpenbankingPackageParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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