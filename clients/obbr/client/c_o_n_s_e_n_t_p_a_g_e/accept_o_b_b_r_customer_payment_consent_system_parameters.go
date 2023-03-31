// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

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

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// NewAcceptOBBRCustomerPaymentConsentSystemParams creates a new AcceptOBBRCustomerPaymentConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAcceptOBBRCustomerPaymentConsentSystemParams() *AcceptOBBRCustomerPaymentConsentSystemParams {
	return &AcceptOBBRCustomerPaymentConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAcceptOBBRCustomerPaymentConsentSystemParamsWithTimeout creates a new AcceptOBBRCustomerPaymentConsentSystemParams object
// with the ability to set a timeout on a request.
func NewAcceptOBBRCustomerPaymentConsentSystemParamsWithTimeout(timeout time.Duration) *AcceptOBBRCustomerPaymentConsentSystemParams {
	return &AcceptOBBRCustomerPaymentConsentSystemParams{
		timeout: timeout,
	}
}

// NewAcceptOBBRCustomerPaymentConsentSystemParamsWithContext creates a new AcceptOBBRCustomerPaymentConsentSystemParams object
// with the ability to set a context for a request.
func NewAcceptOBBRCustomerPaymentConsentSystemParamsWithContext(ctx context.Context) *AcceptOBBRCustomerPaymentConsentSystemParams {
	return &AcceptOBBRCustomerPaymentConsentSystemParams{
		Context: ctx,
	}
}

// NewAcceptOBBRCustomerPaymentConsentSystemParamsWithHTTPClient creates a new AcceptOBBRCustomerPaymentConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewAcceptOBBRCustomerPaymentConsentSystemParamsWithHTTPClient(client *http.Client) *AcceptOBBRCustomerPaymentConsentSystemParams {
	return &AcceptOBBRCustomerPaymentConsentSystemParams{
		HTTPClient: client,
	}
}

/*
AcceptOBBRCustomerPaymentConsentSystemParams contains all the parameters to send to the API endpoint

	for the accept o b b r customer payment consent system operation.

	Typically these are written to a http.Request.
*/
type AcceptOBBRCustomerPaymentConsentSystemParams struct {

	// AcceptConsent.
	AcceptConsent *models.AcceptConsentRequest

	// Login.
	Login string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the accept o b b r customer payment consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) WithDefaults() *AcceptOBBRCustomerPaymentConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the accept o b b r customer payment consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) WithTimeout(timeout time.Duration) *AcceptOBBRCustomerPaymentConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) WithContext(ctx context.Context) *AcceptOBBRCustomerPaymentConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) WithHTTPClient(client *http.Client) *AcceptOBBRCustomerPaymentConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAcceptConsent adds the acceptConsent to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) WithAcceptConsent(acceptConsent *models.AcceptConsentRequest) *AcceptOBBRCustomerPaymentConsentSystemParams {
	o.SetAcceptConsent(acceptConsent)
	return o
}

// SetAcceptConsent adds the acceptConsent to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) SetAcceptConsent(acceptConsent *models.AcceptConsentRequest) {
	o.AcceptConsent = acceptConsent
}

// WithLogin adds the login to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) WithLogin(login string) *AcceptOBBRCustomerPaymentConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the accept o b b r customer payment consent system params
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WriteToRequest writes these params to a swagger request
func (o *AcceptOBBRCustomerPaymentConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.AcceptConsent != nil {
		if err := r.SetBodyParam(o.AcceptConsent); err != nil {
			return err
		}
	}

	// path param login
	if err := r.SetPathParam("login", o.Login); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
