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

	"github.com/cloudentity/acp-client-go/models"
)

// NewRejectOBBRCustomerDataAccessConsentSystemParams creates a new RejectOBBRCustomerDataAccessConsentSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRejectOBBRCustomerDataAccessConsentSystemParams() *RejectOBBRCustomerDataAccessConsentSystemParams {
	return &RejectOBBRCustomerDataAccessConsentSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRejectOBBRCustomerDataAccessConsentSystemParamsWithTimeout creates a new RejectOBBRCustomerDataAccessConsentSystemParams object
// with the ability to set a timeout on a request.
func NewRejectOBBRCustomerDataAccessConsentSystemParamsWithTimeout(timeout time.Duration) *RejectOBBRCustomerDataAccessConsentSystemParams {
	return &RejectOBBRCustomerDataAccessConsentSystemParams{
		timeout: timeout,
	}
}

// NewRejectOBBRCustomerDataAccessConsentSystemParamsWithContext creates a new RejectOBBRCustomerDataAccessConsentSystemParams object
// with the ability to set a context for a request.
func NewRejectOBBRCustomerDataAccessConsentSystemParamsWithContext(ctx context.Context) *RejectOBBRCustomerDataAccessConsentSystemParams {
	return &RejectOBBRCustomerDataAccessConsentSystemParams{
		Context: ctx,
	}
}

// NewRejectOBBRCustomerDataAccessConsentSystemParamsWithHTTPClient creates a new RejectOBBRCustomerDataAccessConsentSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewRejectOBBRCustomerDataAccessConsentSystemParamsWithHTTPClient(client *http.Client) *RejectOBBRCustomerDataAccessConsentSystemParams {
	return &RejectOBBRCustomerDataAccessConsentSystemParams{
		HTTPClient: client,
	}
}

/* RejectOBBRCustomerDataAccessConsentSystemParams contains all the parameters to send to the API endpoint
   for the reject o b b r customer data access consent system operation.

   Typically these are written to a http.Request.
*/
type RejectOBBRCustomerDataAccessConsentSystemParams struct {

	// RejectConsent.
	RejectConsent *models.RejectConsentRequest

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

// WithDefaults hydrates default values in the reject o b b r customer data access consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WithDefaults() *RejectOBBRCustomerDataAccessConsentSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the reject o b b r customer data access consent system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := RejectOBBRCustomerDataAccessConsentSystemParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WithTimeout(timeout time.Duration) *RejectOBBRCustomerDataAccessConsentSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WithContext(ctx context.Context) *RejectOBBRCustomerDataAccessConsentSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WithHTTPClient(client *http.Client) *RejectOBBRCustomerDataAccessConsentSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRejectConsent adds the rejectConsent to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WithRejectConsent(rejectConsent *models.RejectConsentRequest) *RejectOBBRCustomerDataAccessConsentSystemParams {
	o.SetRejectConsent(rejectConsent)
	return o
}

// SetRejectConsent adds the rejectConsent to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) SetRejectConsent(rejectConsent *models.RejectConsentRequest) {
	o.RejectConsent = rejectConsent
}

// WithLogin adds the login to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WithLogin(login string) *RejectOBBRCustomerDataAccessConsentSystemParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) SetLogin(login string) {
	o.Login = login
}

// WithTid adds the tid to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WithTid(tid string) *RejectOBBRCustomerDataAccessConsentSystemParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the reject o b b r customer data access consent system params
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *RejectOBBRCustomerDataAccessConsentSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
