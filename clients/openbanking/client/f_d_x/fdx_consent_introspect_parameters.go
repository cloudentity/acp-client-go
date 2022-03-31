// Code generated by go-swagger; DO NOT EDIT.

package f_d_x

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

// NewFdxConsentIntrospectParams creates a new FdxConsentIntrospectParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewFdxConsentIntrospectParams() *FdxConsentIntrospectParams {
	return &FdxConsentIntrospectParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewFdxConsentIntrospectParamsWithTimeout creates a new FdxConsentIntrospectParams object
// with the ability to set a timeout on a request.
func NewFdxConsentIntrospectParamsWithTimeout(timeout time.Duration) *FdxConsentIntrospectParams {
	return &FdxConsentIntrospectParams{
		timeout: timeout,
	}
}

// NewFdxConsentIntrospectParamsWithContext creates a new FdxConsentIntrospectParams object
// with the ability to set a context for a request.
func NewFdxConsentIntrospectParamsWithContext(ctx context.Context) *FdxConsentIntrospectParams {
	return &FdxConsentIntrospectParams{
		Context: ctx,
	}
}

// NewFdxConsentIntrospectParamsWithHTTPClient creates a new FdxConsentIntrospectParams object
// with the ability to set a custom HTTPClient for a request.
func NewFdxConsentIntrospectParamsWithHTTPClient(client *http.Client) *FdxConsentIntrospectParams {
	return &FdxConsentIntrospectParams{
		HTTPClient: client,
	}
}

/* FdxConsentIntrospectParams contains all the parameters to send to the API endpoint
   for the fdx consent introspect operation.

   Typically these are written to a http.Request.
*/
type FdxConsentIntrospectParams struct {

	// Token.
	Token *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the fdx consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FdxConsentIntrospectParams) WithDefaults() *FdxConsentIntrospectParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the fdx consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *FdxConsentIntrospectParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) WithTimeout(timeout time.Duration) *FdxConsentIntrospectParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) WithContext(ctx context.Context) *FdxConsentIntrospectParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) WithHTTPClient(client *http.Client) *FdxConsentIntrospectParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithToken adds the token to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) WithToken(token *string) *FdxConsentIntrospectParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the fdx consent introspect params
func (o *FdxConsentIntrospectParams) SetToken(token *string) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *FdxConsentIntrospectParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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