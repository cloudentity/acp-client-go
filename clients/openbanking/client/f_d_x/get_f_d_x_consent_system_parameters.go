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

// NewGetFDXConsentSystemParams creates a new GetFDXConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetFDXConsentSystemParams() *GetFDXConsentSystemParams {
	return &GetFDXConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetFDXConsentSystemParamsWithTimeout creates a new GetFDXConsentSystemParams object
// with the ability to set a timeout on a request.
func NewGetFDXConsentSystemParamsWithTimeout(timeout time.Duration) *GetFDXConsentSystemParams {
	return &GetFDXConsentSystemParams{
		timeout: timeout,
	}
}

// NewGetFDXConsentSystemParamsWithContext creates a new GetFDXConsentSystemParams object
// with the ability to set a context for a request.
func NewGetFDXConsentSystemParamsWithContext(ctx context.Context) *GetFDXConsentSystemParams {
	return &GetFDXConsentSystemParams{
		Context: ctx,
	}
}

// NewGetFDXConsentSystemParamsWithHTTPClient creates a new GetFDXConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetFDXConsentSystemParamsWithHTTPClient(client *http.Client) *GetFDXConsentSystemParams {
	return &GetFDXConsentSystemParams{
		HTTPClient: client,
	}
}

/*
GetFDXConsentSystemParams contains all the parameters to send to the API endpoint

	for the get f d x consent system operation.

	Typically these are written to a http.Request.
*/
type GetFDXConsentSystemParams struct {

	// Login.
	Login string

	// LoginState.
	LoginState *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get f d x consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFDXConsentSystemParams) WithDefaults() *GetFDXConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get f d x consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFDXConsentSystemParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get f d x consent system params
func (o *GetFDXConsentSystemParams) WithTimeout(timeout time.Duration) *GetFDXConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get f d x consent system params
func (o *GetFDXConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get f d x consent system params
func (o *GetFDXConsentSystemParams) WithContext(ctx context.Context) *GetFDXConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get f d x consent system params
func (o *GetFDXConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get f d x consent system params
func (o *GetFDXConsentSystemParams) WithHTTPClient(client *http.Client) *GetFDXConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get f d x consent system params
func (o *GetFDXConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLogin adds the login to the get f d x consent system params
func (o *GetFDXConsentSystemParams) WithLogin(login string) *GetFDXConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the get f d x consent system params
func (o *GetFDXConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WithLoginState adds the loginState to the get f d x consent system params
func (o *GetFDXConsentSystemParams) WithLoginState(loginState *string) *GetFDXConsentSystemParams {
	o.SetLoginState(loginState)
	return o
}

// SetLoginState adds the loginState to the get f d x consent system params
func (o *GetFDXConsentSystemParams) SetLoginState(loginState *string) {
	o.LoginState = loginState
}

// WriteToRequest writes these params to a swagger request
func (o *GetFDXConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
