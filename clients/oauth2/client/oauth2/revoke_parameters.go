// Code generated by go-swagger; DO NOT EDIT.

package oauth2

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

// NewRevokeParams creates a new RevokeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRevokeParams() *RevokeParams {
	return &RevokeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRevokeParamsWithTimeout creates a new RevokeParams object
// with the ability to set a timeout on a request.
func NewRevokeParamsWithTimeout(timeout time.Duration) *RevokeParams {
	return &RevokeParams{
		timeout: timeout,
	}
}

// NewRevokeParamsWithContext creates a new RevokeParams object
// with the ability to set a context for a request.
func NewRevokeParamsWithContext(ctx context.Context) *RevokeParams {
	return &RevokeParams{
		Context: ctx,
	}
}

// NewRevokeParamsWithHTTPClient creates a new RevokeParams object
// with the ability to set a custom HTTPClient for a request.
func NewRevokeParamsWithHTTPClient(client *http.Client) *RevokeParams {
	return &RevokeParams{
		HTTPClient: client,
	}
}

/* RevokeParams contains all the parameters to send to the API endpoint
   for the revoke operation.

   Typically these are written to a http.Request.
*/
type RevokeParams struct {

	// Token.
	Token *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the revoke params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeParams) WithDefaults() *RevokeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the revoke params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the revoke params
func (o *RevokeParams) WithTimeout(timeout time.Duration) *RevokeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the revoke params
func (o *RevokeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the revoke params
func (o *RevokeParams) WithContext(ctx context.Context) *RevokeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the revoke params
func (o *RevokeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the revoke params
func (o *RevokeParams) WithHTTPClient(client *http.Client) *RevokeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the revoke params
func (o *RevokeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithToken adds the token to the revoke params
func (o *RevokeParams) WithToken(token *string) *RevokeParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the revoke params
func (o *RevokeParams) SetToken(token *string) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *RevokeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Token != nil {

		// form param token
		var frToken string
		if o.Token != nil {
			frToken = *o.Token
		}
		fToken := frToken
		if fToken != "" {
			if err := r.SetFormParam("token", fToken); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}