// Code generated by go-swagger; DO NOT EDIT.

package mfa

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

// NewListUserMFASessionsParams creates a new ListUserMFASessionsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListUserMFASessionsParams() *ListUserMFASessionsParams {
	return &ListUserMFASessionsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListUserMFASessionsParamsWithTimeout creates a new ListUserMFASessionsParams object
// with the ability to set a timeout on a request.
func NewListUserMFASessionsParamsWithTimeout(timeout time.Duration) *ListUserMFASessionsParams {
	return &ListUserMFASessionsParams{
		timeout: timeout,
	}
}

// NewListUserMFASessionsParamsWithContext creates a new ListUserMFASessionsParams object
// with the ability to set a context for a request.
func NewListUserMFASessionsParamsWithContext(ctx context.Context) *ListUserMFASessionsParams {
	return &ListUserMFASessionsParams{
		Context: ctx,
	}
}

// NewListUserMFASessionsParamsWithHTTPClient creates a new ListUserMFASessionsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListUserMFASessionsParamsWithHTTPClient(client *http.Client) *ListUserMFASessionsParams {
	return &ListUserMFASessionsParams{
		HTTPClient: client,
	}
}

/*
ListUserMFASessionsParams contains all the parameters to send to the API endpoint

	for the list user m f a sessions operation.

	Typically these are written to a http.Request.
*/
type ListUserMFASessionsParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list user m f a sessions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListUserMFASessionsParams) WithDefaults() *ListUserMFASessionsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list user m f a sessions params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListUserMFASessionsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list user m f a sessions params
func (o *ListUserMFASessionsParams) WithTimeout(timeout time.Duration) *ListUserMFASessionsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list user m f a sessions params
func (o *ListUserMFASessionsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list user m f a sessions params
func (o *ListUserMFASessionsParams) WithContext(ctx context.Context) *ListUserMFASessionsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list user m f a sessions params
func (o *ListUserMFASessionsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list user m f a sessions params
func (o *ListUserMFASessionsParams) WithHTTPClient(client *http.Client) *ListUserMFASessionsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list user m f a sessions params
func (o *ListUserMFASessionsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ListUserMFASessionsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
