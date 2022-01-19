// Code generated by go-swagger; DO NOT EDIT.

package openbanking_u_k

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

// NewGetInternationalStandingOrderConsentSystemParams creates a new GetInternationalStandingOrderConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetInternationalStandingOrderConsentSystemParams() *GetInternationalStandingOrderConsentSystemParams {
	return &GetInternationalStandingOrderConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetInternationalStandingOrderConsentSystemParamsWithTimeout creates a new GetInternationalStandingOrderConsentSystemParams object
// with the ability to set a timeout on a request.
func NewGetInternationalStandingOrderConsentSystemParamsWithTimeout(timeout time.Duration) *GetInternationalStandingOrderConsentSystemParams {
	return &GetInternationalStandingOrderConsentSystemParams{
		timeout: timeout,
	}
}

// NewGetInternationalStandingOrderConsentSystemParamsWithContext creates a new GetInternationalStandingOrderConsentSystemParams object
// with the ability to set a context for a request.
func NewGetInternationalStandingOrderConsentSystemParamsWithContext(ctx context.Context) *GetInternationalStandingOrderConsentSystemParams {
	return &GetInternationalStandingOrderConsentSystemParams{
		Context: ctx,
	}
}

// NewGetInternationalStandingOrderConsentSystemParamsWithHTTPClient creates a new GetInternationalStandingOrderConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetInternationalStandingOrderConsentSystemParamsWithHTTPClient(client *http.Client) *GetInternationalStandingOrderConsentSystemParams {
	return &GetInternationalStandingOrderConsentSystemParams{
		HTTPClient: client,
	}
}

/* GetInternationalStandingOrderConsentSystemParams contains all the parameters to send to the API endpoint
   for the get international standing order consent system operation.

   Typically these are written to a http.Request.
*/
type GetInternationalStandingOrderConsentSystemParams struct {

	// Login.
	Login string

	// LoginState.
	LoginState *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get international standing order consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetInternationalStandingOrderConsentSystemParams) WithDefaults() *GetInternationalStandingOrderConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get international standing order consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetInternationalStandingOrderConsentSystemParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) WithTimeout(timeout time.Duration) *GetInternationalStandingOrderConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) WithContext(ctx context.Context) *GetInternationalStandingOrderConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) WithHTTPClient(client *http.Client) *GetInternationalStandingOrderConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLogin adds the login to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) WithLogin(login string) *GetInternationalStandingOrderConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WithLoginState adds the loginState to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) WithLoginState(loginState *string) *GetInternationalStandingOrderConsentSystemParams {
	o.SetLoginState(loginState)
	return o
}

// SetLoginState adds the loginState to the get international standing order consent system params
func (o *GetInternationalStandingOrderConsentSystemParams) SetLoginState(loginState *string) {
	o.LoginState = loginState
}

// WriteToRequest writes these params to a swagger request
func (o *GetInternationalStandingOrderConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param login
	if err := r.SetPathParam("login", o.Login); err != nil {
		return err
	}

	if o.LoginState != nil {

		// query param login_state
		var qrLoginState string

		if o.LoginState != nil {
			qrLoginState = *o.LoginState
		}
		qLoginState := qrLoginState
		if qLoginState != "" {

			if err := r.SetQueryParam("login_state", qLoginState); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
