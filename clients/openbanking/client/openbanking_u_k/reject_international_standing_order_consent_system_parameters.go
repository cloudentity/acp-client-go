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

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// NewRejectInternationalStandingOrderConsentSystemParams creates a new RejectInternationalStandingOrderConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRejectInternationalStandingOrderConsentSystemParams() *RejectInternationalStandingOrderConsentSystemParams {
	return &RejectInternationalStandingOrderConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRejectInternationalStandingOrderConsentSystemParamsWithTimeout creates a new RejectInternationalStandingOrderConsentSystemParams object
// with the ability to set a timeout on a request.
func NewRejectInternationalStandingOrderConsentSystemParamsWithTimeout(timeout time.Duration) *RejectInternationalStandingOrderConsentSystemParams {
	return &RejectInternationalStandingOrderConsentSystemParams{
		timeout: timeout,
	}
}

// NewRejectInternationalStandingOrderConsentSystemParamsWithContext creates a new RejectInternationalStandingOrderConsentSystemParams object
// with the ability to set a context for a request.
func NewRejectInternationalStandingOrderConsentSystemParamsWithContext(ctx context.Context) *RejectInternationalStandingOrderConsentSystemParams {
	return &RejectInternationalStandingOrderConsentSystemParams{
		Context: ctx,
	}
}

// NewRejectInternationalStandingOrderConsentSystemParamsWithHTTPClient creates a new RejectInternationalStandingOrderConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewRejectInternationalStandingOrderConsentSystemParamsWithHTTPClient(client *http.Client) *RejectInternationalStandingOrderConsentSystemParams {
	return &RejectInternationalStandingOrderConsentSystemParams{
		HTTPClient: client,
	}
}

/* RejectInternationalStandingOrderConsentSystemParams contains all the parameters to send to the API endpoint
   for the reject international standing order consent system operation.

   Typically these are written to a http.Request.
*/
type RejectInternationalStandingOrderConsentSystemParams struct {

	// RejectConsent.
	RejectConsent *models.RejectConsentRequest

	// Login.
	Login string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the reject international standing order consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RejectInternationalStandingOrderConsentSystemParams) WithDefaults() *RejectInternationalStandingOrderConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the reject international standing order consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RejectInternationalStandingOrderConsentSystemParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) WithTimeout(timeout time.Duration) *RejectInternationalStandingOrderConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) WithContext(ctx context.Context) *RejectInternationalStandingOrderConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) WithHTTPClient(client *http.Client) *RejectInternationalStandingOrderConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRejectConsent adds the rejectConsent to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) WithRejectConsent(rejectConsent *models.RejectConsentRequest) *RejectInternationalStandingOrderConsentSystemParams {
	o.SetRejectConsent(rejectConsent)
	return o
}

// SetRejectConsent adds the rejectConsent to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) SetRejectConsent(rejectConsent *models.RejectConsentRequest) {
	o.RejectConsent = rejectConsent
}

// WithLogin adds the login to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) WithLogin(login string) *RejectInternationalStandingOrderConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the reject international standing order consent system params
func (o *RejectInternationalStandingOrderConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WriteToRequest writes these params to a swagger request
func (o *RejectInternationalStandingOrderConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.RejectConsent != nil {
		if err := r.SetBodyParam(o.RejectConsent); err != nil {
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
