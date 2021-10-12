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

// NewGetFilePaymentConsentSystemParams creates a new GetFilePaymentConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetFilePaymentConsentSystemParams() *GetFilePaymentConsentSystemParams {
	return &GetFilePaymentConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetFilePaymentConsentSystemParamsWithTimeout creates a new GetFilePaymentConsentSystemParams object
// with the ability to set a timeout on a request.
func NewGetFilePaymentConsentSystemParamsWithTimeout(timeout time.Duration) *GetFilePaymentConsentSystemParams {
	return &GetFilePaymentConsentSystemParams{
		timeout: timeout,
	}
}

// NewGetFilePaymentConsentSystemParamsWithContext creates a new GetFilePaymentConsentSystemParams object
// with the ability to set a context for a request.
func NewGetFilePaymentConsentSystemParamsWithContext(ctx context.Context) *GetFilePaymentConsentSystemParams {
	return &GetFilePaymentConsentSystemParams{
		Context: ctx,
	}
}

// NewGetFilePaymentConsentSystemParamsWithHTTPClient creates a new GetFilePaymentConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetFilePaymentConsentSystemParamsWithHTTPClient(client *http.Client) *GetFilePaymentConsentSystemParams {
	return &GetFilePaymentConsentSystemParams{
		HTTPClient: client,
	}
}

/* GetFilePaymentConsentSystemParams contains all the parameters to send to the API endpoint
   for the get file payment consent system operation.

   Typically these are written to a http.Request.
*/
type GetFilePaymentConsentSystemParams struct {

	// Login.
	Login string

	// LoginState.
	LoginState *string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get file payment consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFilePaymentConsentSystemParams) WithDefaults() *GetFilePaymentConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get file payment consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetFilePaymentConsentSystemParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := GetFilePaymentConsentSystemParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) WithTimeout(timeout time.Duration) *GetFilePaymentConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) WithContext(ctx context.Context) *GetFilePaymentConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) WithHTTPClient(client *http.Client) *GetFilePaymentConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLogin adds the login to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) WithLogin(login string) *GetFilePaymentConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WithLoginState adds the loginState to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) WithLoginState(loginState *string) *GetFilePaymentConsentSystemParams {
	o.SetLoginState(loginState)
	return o
}

// SetLoginState adds the loginState to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) SetLoginState(loginState *string) {
	o.LoginState = loginState
}

// WithTid adds the tid to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) WithTid(tid string) *GetFilePaymentConsentSystemParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get file payment consent system params
func (o *GetFilePaymentConsentSystemParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *GetFilePaymentConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}