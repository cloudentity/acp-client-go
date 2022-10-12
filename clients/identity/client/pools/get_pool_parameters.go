// Code generated by go-swagger; DO NOT EDIT.

package pools

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

// NewGetPoolParams creates a new GetPoolParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetPoolParams() *GetPoolParams {
	return &GetPoolParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetPoolParamsWithTimeout creates a new GetPoolParams object
// with the ability to set a timeout on a request.
func NewGetPoolParamsWithTimeout(timeout time.Duration) *GetPoolParams {
	return &GetPoolParams{
		timeout: timeout,
	}
}

// NewGetPoolParamsWithContext creates a new GetPoolParams object
// with the ability to set a context for a request.
func NewGetPoolParamsWithContext(ctx context.Context) *GetPoolParams {
	return &GetPoolParams{
		Context: ctx,
	}
}

// NewGetPoolParamsWithHTTPClient creates a new GetPoolParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetPoolParamsWithHTTPClient(client *http.Client) *GetPoolParams {
	return &GetPoolParams{
		HTTPClient: client,
	}
}

/*
GetPoolParams contains all the parameters to send to the API endpoint

	for the get pool operation.

	Typically these are written to a http.Request.
*/
type GetPoolParams struct {

	// IPID.
	IPID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPoolParams) WithDefaults() *GetPoolParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPoolParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get pool params
func (o *GetPoolParams) WithTimeout(timeout time.Duration) *GetPoolParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get pool params
func (o *GetPoolParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get pool params
func (o *GetPoolParams) WithContext(ctx context.Context) *GetPoolParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get pool params
func (o *GetPoolParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get pool params
func (o *GetPoolParams) WithHTTPClient(client *http.Client) *GetPoolParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get pool params
func (o *GetPoolParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIPID adds the iPID to the get pool params
func (o *GetPoolParams) WithIPID(iPID string) *GetPoolParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the get pool params
func (o *GetPoolParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WriteToRequest writes these params to a swagger request
func (o *GetPoolParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
