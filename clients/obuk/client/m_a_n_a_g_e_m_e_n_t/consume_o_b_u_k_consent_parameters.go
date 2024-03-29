// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

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

// NewConsumeOBUKConsentParams creates a new ConsumeOBUKConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConsumeOBUKConsentParams() *ConsumeOBUKConsentParams {
	return &ConsumeOBUKConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConsumeOBUKConsentParamsWithTimeout creates a new ConsumeOBUKConsentParams object
// with the ability to set a timeout on a request.
func NewConsumeOBUKConsentParamsWithTimeout(timeout time.Duration) *ConsumeOBUKConsentParams {
	return &ConsumeOBUKConsentParams{
		timeout: timeout,
	}
}

// NewConsumeOBUKConsentParamsWithContext creates a new ConsumeOBUKConsentParams object
// with the ability to set a context for a request.
func NewConsumeOBUKConsentParamsWithContext(ctx context.Context) *ConsumeOBUKConsentParams {
	return &ConsumeOBUKConsentParams{
		Context: ctx,
	}
}

// NewConsumeOBUKConsentParamsWithHTTPClient creates a new ConsumeOBUKConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewConsumeOBUKConsentParamsWithHTTPClient(client *http.Client) *ConsumeOBUKConsentParams {
	return &ConsumeOBUKConsentParams{
		HTTPClient: client,
	}
}

/*
ConsumeOBUKConsentParams contains all the parameters to send to the API endpoint

	for the consume o b u k consent operation.

	Typically these are written to a http.Request.
*/
type ConsumeOBUKConsentParams struct {

	// ConsentID.
	ConsentID string

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the consume o b u k consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConsumeOBUKConsentParams) WithDefaults() *ConsumeOBUKConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the consume o b u k consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConsumeOBUKConsentParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := ConsumeOBUKConsentParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) WithTimeout(timeout time.Duration) *ConsumeOBUKConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) WithContext(ctx context.Context) *ConsumeOBUKConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) WithHTTPClient(client *http.Client) *ConsumeOBUKConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsentID adds the consentID to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) WithConsentID(consentID string) *ConsumeOBUKConsentParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WithWid adds the wid to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) WithWid(wid string) *ConsumeOBUKConsentParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the consume o b u k consent params
func (o *ConsumeOBUKConsentParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ConsumeOBUKConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param consentID
	if err := r.SetPathParam("consentID", o.ConsentID); err != nil {
		return err
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
