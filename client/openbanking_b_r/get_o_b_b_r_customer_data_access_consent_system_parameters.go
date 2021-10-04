// Code generated by go-swagger; DO NOT EDIT.

package openbanking_b_r

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

// NewGetOBBRCustomerDataAccessConsentSystemParams creates a new GetOBBRCustomerDataAccessConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetOBBRCustomerDataAccessConsentSystemParams() *GetOBBRCustomerDataAccessConsentSystemParams {
	return &GetOBBRCustomerDataAccessConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetOBBRCustomerDataAccessConsentSystemParamsWithTimeout creates a new GetOBBRCustomerDataAccessConsentSystemParams object
// with the ability to set a timeout on a request.
func NewGetOBBRCustomerDataAccessConsentSystemParamsWithTimeout(timeout time.Duration) *GetOBBRCustomerDataAccessConsentSystemParams {
	return &GetOBBRCustomerDataAccessConsentSystemParams{
		timeout: timeout,
	}
}

// NewGetOBBRCustomerDataAccessConsentSystemParamsWithContext creates a new GetOBBRCustomerDataAccessConsentSystemParams object
// with the ability to set a context for a request.
func NewGetOBBRCustomerDataAccessConsentSystemParamsWithContext(ctx context.Context) *GetOBBRCustomerDataAccessConsentSystemParams {
	return &GetOBBRCustomerDataAccessConsentSystemParams{
		Context: ctx,
	}
}

// NewGetOBBRCustomerDataAccessConsentSystemParamsWithHTTPClient creates a new GetOBBRCustomerDataAccessConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetOBBRCustomerDataAccessConsentSystemParamsWithHTTPClient(client *http.Client) *GetOBBRCustomerDataAccessConsentSystemParams {
	return &GetOBBRCustomerDataAccessConsentSystemParams{
		HTTPClient: client,
	}
}

/* GetOBBRCustomerDataAccessConsentSystemParams contains all the parameters to send to the API endpoint
   for the get o b b r customer data access consent system operation.

   Typically these are written to a http.Request.
*/
type GetOBBRCustomerDataAccessConsentSystemParams struct {

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

// WithDefaults hydrates default values in the get o b b r customer data access consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WithDefaults() *GetOBBRCustomerDataAccessConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get o b b r customer data access consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOBBRCustomerDataAccessConsentSystemParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := GetOBBRCustomerDataAccessConsentSystemParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WithTimeout(timeout time.Duration) *GetOBBRCustomerDataAccessConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WithContext(ctx context.Context) *GetOBBRCustomerDataAccessConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WithHTTPClient(client *http.Client) *GetOBBRCustomerDataAccessConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLogin adds the login to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WithLogin(login string) *GetOBBRCustomerDataAccessConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WithLoginState adds the loginState to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WithLoginState(loginState *string) *GetOBBRCustomerDataAccessConsentSystemParams {
	o.SetLoginState(loginState)
	return o
}

// SetLoginState adds the loginState to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) SetLoginState(loginState *string) {
	o.LoginState = loginState
}

// WithTid adds the tid to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WithTid(tid string) *GetOBBRCustomerDataAccessConsentSystemParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get o b b r customer data access consent system params
func (o *GetOBBRCustomerDataAccessConsentSystemParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *GetOBBRCustomerDataAccessConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
