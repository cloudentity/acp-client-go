// Code generated by go-swagger; DO NOT EDIT.

package b2_b_users

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

// NewGetB2BUserParams creates a new GetB2BUserParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetB2BUserParams() *GetB2BUserParams {
	return &GetB2BUserParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetB2BUserParamsWithTimeout creates a new GetB2BUserParams object
// with the ability to set a timeout on a request.
func NewGetB2BUserParamsWithTimeout(timeout time.Duration) *GetB2BUserParams {
	return &GetB2BUserParams{
		timeout: timeout,
	}
}

// NewGetB2BUserParamsWithContext creates a new GetB2BUserParams object
// with the ability to set a context for a request.
func NewGetB2BUserParamsWithContext(ctx context.Context) *GetB2BUserParams {
	return &GetB2BUserParams{
		Context: ctx,
	}
}

// NewGetB2BUserParamsWithHTTPClient creates a new GetB2BUserParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetB2BUserParamsWithHTTPClient(client *http.Client) *GetB2BUserParams {
	return &GetB2BUserParams{
		HTTPClient: client,
	}
}

/*
GetB2BUserParams contains all the parameters to send to the API endpoint

	for the get b2 b user operation.

	Typically these are written to a http.Request.
*/
type GetB2BUserParams struct {

	// IPID.
	IPID string

	// UserID.
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get b2 b user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetB2BUserParams) WithDefaults() *GetB2BUserParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get b2 b user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetB2BUserParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get b2 b user params
func (o *GetB2BUserParams) WithTimeout(timeout time.Duration) *GetB2BUserParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get b2 b user params
func (o *GetB2BUserParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get b2 b user params
func (o *GetB2BUserParams) WithContext(ctx context.Context) *GetB2BUserParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get b2 b user params
func (o *GetB2BUserParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get b2 b user params
func (o *GetB2BUserParams) WithHTTPClient(client *http.Client) *GetB2BUserParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get b2 b user params
func (o *GetB2BUserParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIPID adds the iPID to the get b2 b user params
func (o *GetB2BUserParams) WithIPID(iPID string) *GetB2BUserParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the get b2 b user params
func (o *GetB2BUserParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithUserID adds the userID to the get b2 b user params
func (o *GetB2BUserParams) WithUserID(userID string) *GetB2BUserParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the get b2 b user params
func (o *GetB2BUserParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *GetB2BUserParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
