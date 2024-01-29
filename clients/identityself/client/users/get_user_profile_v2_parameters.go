// Code generated by go-swagger; DO NOT EDIT.

package users

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

// NewGetUserProfileV2Params creates a new GetUserProfileV2Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetUserProfileV2Params() *GetUserProfileV2Params {
	return &GetUserProfileV2Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetUserProfileV2ParamsWithTimeout creates a new GetUserProfileV2Params object
// with the ability to set a timeout on a request.
func NewGetUserProfileV2ParamsWithTimeout(timeout time.Duration) *GetUserProfileV2Params {
	return &GetUserProfileV2Params{
		timeout: timeout,
	}
}

// NewGetUserProfileV2ParamsWithContext creates a new GetUserProfileV2Params object
// with the ability to set a context for a request.
func NewGetUserProfileV2ParamsWithContext(ctx context.Context) *GetUserProfileV2Params {
	return &GetUserProfileV2Params{
		Context: ctx,
	}
}

// NewGetUserProfileV2ParamsWithHTTPClient creates a new GetUserProfileV2Params object
// with the ability to set a custom HTTPClient for a request.
func NewGetUserProfileV2ParamsWithHTTPClient(client *http.Client) *GetUserProfileV2Params {
	return &GetUserProfileV2Params{
		HTTPClient: client,
	}
}

/*
GetUserProfileV2Params contains all the parameters to send to the API endpoint

	for the get user profile v2 operation.

	Typically these are written to a http.Request.
*/
type GetUserProfileV2Params struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get user profile v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetUserProfileV2Params) WithDefaults() *GetUserProfileV2Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get user profile v2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetUserProfileV2Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get user profile v2 params
func (o *GetUserProfileV2Params) WithTimeout(timeout time.Duration) *GetUserProfileV2Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get user profile v2 params
func (o *GetUserProfileV2Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get user profile v2 params
func (o *GetUserProfileV2Params) WithContext(ctx context.Context) *GetUserProfileV2Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get user profile v2 params
func (o *GetUserProfileV2Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get user profile v2 params
func (o *GetUserProfileV2Params) WithHTTPClient(client *http.Client) *GetUserProfileV2Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get user profile v2 params
func (o *GetUserProfileV2Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *GetUserProfileV2Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
