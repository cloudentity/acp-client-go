// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

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

// NewDeleteMFAMethodParams creates a new DeleteMFAMethodParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteMFAMethodParams() *DeleteMFAMethodParams {
	return &DeleteMFAMethodParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteMFAMethodParamsWithTimeout creates a new DeleteMFAMethodParams object
// with the ability to set a timeout on a request.
func NewDeleteMFAMethodParamsWithTimeout(timeout time.Duration) *DeleteMFAMethodParams {
	return &DeleteMFAMethodParams{
		timeout: timeout,
	}
}

// NewDeleteMFAMethodParamsWithContext creates a new DeleteMFAMethodParams object
// with the ability to set a context for a request.
func NewDeleteMFAMethodParamsWithContext(ctx context.Context) *DeleteMFAMethodParams {
	return &DeleteMFAMethodParams{
		Context: ctx,
	}
}

// NewDeleteMFAMethodParamsWithHTTPClient creates a new DeleteMFAMethodParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteMFAMethodParamsWithHTTPClient(client *http.Client) *DeleteMFAMethodParams {
	return &DeleteMFAMethodParams{
		HTTPClient: client,
	}
}

/*
DeleteMFAMethodParams contains all the parameters to send to the API endpoint

	for the delete m f a method operation.

	Typically these are written to a http.Request.
*/
type DeleteMFAMethodParams struct {

	// MfaID.
	MfaID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete m f a method params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteMFAMethodParams) WithDefaults() *DeleteMFAMethodParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete m f a method params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteMFAMethodParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete m f a method params
func (o *DeleteMFAMethodParams) WithTimeout(timeout time.Duration) *DeleteMFAMethodParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete m f a method params
func (o *DeleteMFAMethodParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete m f a method params
func (o *DeleteMFAMethodParams) WithContext(ctx context.Context) *DeleteMFAMethodParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete m f a method params
func (o *DeleteMFAMethodParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete m f a method params
func (o *DeleteMFAMethodParams) WithHTTPClient(client *http.Client) *DeleteMFAMethodParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete m f a method params
func (o *DeleteMFAMethodParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMfaID adds the mfaID to the delete m f a method params
func (o *DeleteMFAMethodParams) WithMfaID(mfaID string) *DeleteMFAMethodParams {
	o.SetMfaID(mfaID)
	return o
}

// SetMfaID adds the mfaId to the delete m f a method params
func (o *DeleteMFAMethodParams) SetMfaID(mfaID string) {
	o.MfaID = mfaID
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteMFAMethodParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param mfaID
	if err := r.SetPathParam("mfaID", o.MfaID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
