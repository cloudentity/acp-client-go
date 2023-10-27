// Code generated by go-swagger; DO NOT EDIT.

package web

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

// NewGetStylingParams creates a new GetStylingParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetStylingParams() *GetStylingParams {
	return &GetStylingParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetStylingParamsWithTimeout creates a new GetStylingParams object
// with the ability to set a timeout on a request.
func NewGetStylingParamsWithTimeout(timeout time.Duration) *GetStylingParams {
	return &GetStylingParams{
		timeout: timeout,
	}
}

// NewGetStylingParamsWithContext creates a new GetStylingParams object
// with the ability to set a context for a request.
func NewGetStylingParamsWithContext(ctx context.Context) *GetStylingParams {
	return &GetStylingParams{
		Context: ctx,
	}
}

// NewGetStylingParamsWithHTTPClient creates a new GetStylingParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetStylingParamsWithHTTPClient(client *http.Client) *GetStylingParams {
	return &GetStylingParams{
		HTTPClient: client,
	}
}

/*
GetStylingParams contains all the parameters to send to the API endpoint

	for the get styling operation.

	Typically these are written to a http.Request.
*/
type GetStylingParams struct {

	/* Aid.

	   Authorization server id

	   Default: "admin"
	*/
	Aid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get styling params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetStylingParams) WithDefaults() *GetStylingParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get styling params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetStylingParams) SetDefaults() {
	var (
		aidDefault = string("admin")
	)

	val := GetStylingParams{
		Aid: aidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get styling params
func (o *GetStylingParams) WithTimeout(timeout time.Duration) *GetStylingParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get styling params
func (o *GetStylingParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get styling params
func (o *GetStylingParams) WithContext(ctx context.Context) *GetStylingParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get styling params
func (o *GetStylingParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get styling params
func (o *GetStylingParams) WithHTTPClient(client *http.Client) *GetStylingParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get styling params
func (o *GetStylingParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the get styling params
func (o *GetStylingParams) WithAid(aid string) *GetStylingParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the get styling params
func (o *GetStylingParams) SetAid(aid string) {
	o.Aid = aid
}

// WriteToRequest writes these params to a swagger request
func (o *GetStylingParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
