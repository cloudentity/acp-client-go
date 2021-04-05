// Code generated by go-swagger; DO NOT EDIT.

package openbanking

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

	"github.com/cloudentity/acp-client-go/models"
)

// NewAcceptDomesticScheduledPaymentConsentSystemParams creates a new AcceptDomesticScheduledPaymentConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAcceptDomesticScheduledPaymentConsentSystemParams() *AcceptDomesticScheduledPaymentConsentSystemParams {
	return &AcceptDomesticScheduledPaymentConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAcceptDomesticScheduledPaymentConsentSystemParamsWithTimeout creates a new AcceptDomesticScheduledPaymentConsentSystemParams object
// with the ability to set a timeout on a request.
func NewAcceptDomesticScheduledPaymentConsentSystemParamsWithTimeout(timeout time.Duration) *AcceptDomesticScheduledPaymentConsentSystemParams {
	return &AcceptDomesticScheduledPaymentConsentSystemParams{
		timeout: timeout,
	}
}

// NewAcceptDomesticScheduledPaymentConsentSystemParamsWithContext creates a new AcceptDomesticScheduledPaymentConsentSystemParams object
// with the ability to set a context for a request.
func NewAcceptDomesticScheduledPaymentConsentSystemParamsWithContext(ctx context.Context) *AcceptDomesticScheduledPaymentConsentSystemParams {
	return &AcceptDomesticScheduledPaymentConsentSystemParams{
		Context: ctx,
	}
}

// NewAcceptDomesticScheduledPaymentConsentSystemParamsWithHTTPClient creates a new AcceptDomesticScheduledPaymentConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewAcceptDomesticScheduledPaymentConsentSystemParamsWithHTTPClient(client *http.Client) *AcceptDomesticScheduledPaymentConsentSystemParams {
	return &AcceptDomesticScheduledPaymentConsentSystemParams{
		HTTPClient: client,
	}
}

/* AcceptDomesticScheduledPaymentConsentSystemParams contains all the parameters to send to the API endpoint
   for the accept domestic scheduled payment consent system operation.

   Typically these are written to a http.Request.
*/
type AcceptDomesticScheduledPaymentConsentSystemParams struct {

	// AcceptDomesticScheduledPaymentConsent.
	AcceptDomesticScheduledPaymentConsent *models.AcceptDomesticScheduledPaymentConsentRequest

	// Login.
	LoginID string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the accept domestic scheduled payment consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WithDefaults() *AcceptDomesticScheduledPaymentConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the accept domestic scheduled payment consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := AcceptDomesticScheduledPaymentConsentSystemParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WithTimeout(timeout time.Duration) *AcceptDomesticScheduledPaymentConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WithContext(ctx context.Context) *AcceptDomesticScheduledPaymentConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WithHTTPClient(client *http.Client) *AcceptDomesticScheduledPaymentConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAcceptDomesticScheduledPaymentConsent adds the acceptDomesticScheduledPaymentConsent to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WithAcceptDomesticScheduledPaymentConsent(acceptDomesticScheduledPaymentConsent *models.AcceptDomesticScheduledPaymentConsentRequest) *AcceptDomesticScheduledPaymentConsentSystemParams {
	o.SetAcceptDomesticScheduledPaymentConsent(acceptDomesticScheduledPaymentConsent)
	return o
}

// SetAcceptDomesticScheduledPaymentConsent adds the acceptDomesticScheduledPaymentConsent to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) SetAcceptDomesticScheduledPaymentConsent(acceptDomesticScheduledPaymentConsent *models.AcceptDomesticScheduledPaymentConsentRequest) {
	o.AcceptDomesticScheduledPaymentConsent = acceptDomesticScheduledPaymentConsent
}

// WithLoginID adds the login to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WithLoginID(login string) *AcceptDomesticScheduledPaymentConsentSystemParams {
	o.SetLoginID(login)
	return o
}

// SetLoginID adds the login to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) SetLoginID(login string) {
	o.LoginID = login
}

// WithTid adds the tid to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WithTid(tid string) *AcceptDomesticScheduledPaymentConsentSystemParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the accept domestic scheduled payment consent system params
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *AcceptDomesticScheduledPaymentConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.AcceptDomesticScheduledPaymentConsent != nil {
		if err := r.SetBodyParam(o.AcceptDomesticScheduledPaymentConsent); err != nil {
			return err
		}
	}

	// path param login
	if err := r.SetPathParam("login", o.LoginID); err != nil {
		return err
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
