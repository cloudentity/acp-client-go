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

// NewDeletePoolParams creates a new DeletePoolParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeletePoolParams() *DeletePoolParams {
	return &DeletePoolParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeletePoolParamsWithTimeout creates a new DeletePoolParams object
// with the ability to set a timeout on a request.
func NewDeletePoolParamsWithTimeout(timeout time.Duration) *DeletePoolParams {
	return &DeletePoolParams{
		timeout: timeout,
	}
}

// NewDeletePoolParamsWithContext creates a new DeletePoolParams object
// with the ability to set a context for a request.
func NewDeletePoolParamsWithContext(ctx context.Context) *DeletePoolParams {
	return &DeletePoolParams{
		Context: ctx,
	}
}

// NewDeletePoolParamsWithHTTPClient creates a new DeletePoolParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeletePoolParamsWithHTTPClient(client *http.Client) *DeletePoolParams {
	return &DeletePoolParams{
		HTTPClient: client,
	}
}

/*
DeletePoolParams contains all the parameters to send to the API endpoint

	for the delete pool operation.

	Typically these are written to a http.Request.
*/
type DeletePoolParams struct {

	// IPID.
	IPID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeletePoolParams) WithDefaults() *DeletePoolParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeletePoolParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete pool params
func (o *DeletePoolParams) WithTimeout(timeout time.Duration) *DeletePoolParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete pool params
func (o *DeletePoolParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete pool params
func (o *DeletePoolParams) WithContext(ctx context.Context) *DeletePoolParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete pool params
func (o *DeletePoolParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete pool params
func (o *DeletePoolParams) WithHTTPClient(client *http.Client) *DeletePoolParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete pool params
func (o *DeletePoolParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIPID adds the iPID to the delete pool params
func (o *DeletePoolParams) WithIPID(iPID string) *DeletePoolParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the delete pool params
func (o *DeletePoolParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WriteToRequest writes these params to a swagger request
func (o *DeletePoolParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
