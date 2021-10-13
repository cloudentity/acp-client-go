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

	"github.com/cloudentity/acp-client-go/acp/models"
)

// NewAcceptDomesticStandingOrderConsentSystemParams creates a new AcceptDomesticStandingOrderConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAcceptDomesticStandingOrderConsentSystemParams() *AcceptDomesticStandingOrderConsentSystemParams {
	return &AcceptDomesticStandingOrderConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAcceptDomesticStandingOrderConsentSystemParamsWithTimeout creates a new AcceptDomesticStandingOrderConsentSystemParams object
// with the ability to set a timeout on a request.
func NewAcceptDomesticStandingOrderConsentSystemParamsWithTimeout(timeout time.Duration) *AcceptDomesticStandingOrderConsentSystemParams {
	return &AcceptDomesticStandingOrderConsentSystemParams{
		timeout: timeout,
	}
}

// NewAcceptDomesticStandingOrderConsentSystemParamsWithContext creates a new AcceptDomesticStandingOrderConsentSystemParams object
// with the ability to set a context for a request.
func NewAcceptDomesticStandingOrderConsentSystemParamsWithContext(ctx context.Context) *AcceptDomesticStandingOrderConsentSystemParams {
	return &AcceptDomesticStandingOrderConsentSystemParams{
		Context: ctx,
	}
}

// NewAcceptDomesticStandingOrderConsentSystemParamsWithHTTPClient creates a new AcceptDomesticStandingOrderConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewAcceptDomesticStandingOrderConsentSystemParamsWithHTTPClient(client *http.Client) *AcceptDomesticStandingOrderConsentSystemParams {
	return &AcceptDomesticStandingOrderConsentSystemParams{
		HTTPClient: client,
	}
}

/* AcceptDomesticStandingOrderConsentSystemParams contains all the parameters to send to the API endpoint
   for the accept domestic standing order consent system operation.

   Typically these are written to a http.Request.
*/
type AcceptDomesticStandingOrderConsentSystemParams struct {

	// AcceptConsent.
	AcceptConsent *models.AcceptConsentRequest

	// Login.
	Login string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the accept domestic standing order consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptDomesticStandingOrderConsentSystemParams) WithDefaults() *AcceptDomesticStandingOrderConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the accept domestic standing order consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AcceptDomesticStandingOrderConsentSystemParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := AcceptDomesticStandingOrderConsentSystemParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) WithTimeout(timeout time.Duration) *AcceptDomesticStandingOrderConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) WithContext(ctx context.Context) *AcceptDomesticStandingOrderConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) WithHTTPClient(client *http.Client) *AcceptDomesticStandingOrderConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAcceptConsent adds the acceptConsent to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) WithAcceptConsent(acceptConsent *models.AcceptConsentRequest) *AcceptDomesticStandingOrderConsentSystemParams {
	o.SetAcceptConsent(acceptConsent)
	return o
}

// SetAcceptConsent adds the acceptConsent to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) SetAcceptConsent(acceptConsent *models.AcceptConsentRequest) {
	o.AcceptConsent = acceptConsent
}

// WithLogin adds the login to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) WithLogin(login string) *AcceptDomesticStandingOrderConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WithTid adds the tid to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) WithTid(tid string) *AcceptDomesticStandingOrderConsentSystemParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the accept domestic standing order consent system params
func (o *AcceptDomesticStandingOrderConsentSystemParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *AcceptDomesticStandingOrderConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}