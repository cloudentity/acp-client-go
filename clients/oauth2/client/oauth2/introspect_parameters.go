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
	"github.com/go-openapi/swag"
)

// NewIntrospectParams creates a new IntrospectParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIntrospectParams() *IntrospectParams {
	return &IntrospectParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewIntrospectParamsWithTimeout creates a new IntrospectParams object
// with the ability to set a timeout on a request.
func NewIntrospectParamsWithTimeout(timeout time.Duration) *IntrospectParams {
	return &IntrospectParams{
		timeout: timeout,
	}
}

// NewIntrospectParamsWithContext creates a new IntrospectParams object
// with the ability to set a context for a request.
func NewIntrospectParamsWithContext(ctx context.Context) *IntrospectParams {
	return &IntrospectParams{
		Context: ctx,
	}
}

// NewIntrospectParamsWithHTTPClient creates a new IntrospectParams object
// with the ability to set a custom HTTPClient for a request.
func NewIntrospectParamsWithHTTPClient(client *http.Client) *IntrospectParams {
	return &IntrospectParams{
		HTTPClient: client,
	}
}

/*
IntrospectParams contains all the parameters to send to the API endpoint

	for the introspect operation.

	Typically these are written to a http.Request.
*/
type IntrospectParams struct {

	/* SSOSessionExtend.

	   Indicates if sso session should be extended for the request. Optional. Default `true`
	*/
	SSOSessionExtend *bool

	// Token.
	Token *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntrospectParams) WithDefaults() *IntrospectParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntrospectParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the introspect params
func (o *IntrospectParams) WithTimeout(timeout time.Duration) *IntrospectParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the introspect params
func (o *IntrospectParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the introspect params
func (o *IntrospectParams) WithContext(ctx context.Context) *IntrospectParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the introspect params
func (o *IntrospectParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the introspect params
func (o *IntrospectParams) WithHTTPClient(client *http.Client) *IntrospectParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the introspect params
func (o *IntrospectParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSSOSessionExtend adds the sSOSessionExtend to the introspect params
func (o *IntrospectParams) WithSSOSessionExtend(sSOSessionExtend *bool) *IntrospectParams {
	o.SetSSOSessionExtend(sSOSessionExtend)
	return o
}

// SetSSOSessionExtend adds the sSOSessionExtend to the introspect params
func (o *IntrospectParams) SetSSOSessionExtend(sSOSessionExtend *bool) {
	o.SSOSessionExtend = sSOSessionExtend
}

// WithToken adds the token to the introspect params
func (o *IntrospectParams) WithToken(token *string) *IntrospectParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the introspect params
func (o *IntrospectParams) SetToken(token *string) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *IntrospectParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.SSOSessionExtend != nil {

		// header param SSO-Session-Extend
		if err := r.SetHeaderParam("SSO-Session-Extend", swag.FormatBool(*o.SSOSessionExtend)); err != nil {
			return err
		}
	}

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
