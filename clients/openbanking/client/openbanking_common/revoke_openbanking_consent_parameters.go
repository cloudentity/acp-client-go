// Code generated by go-swagger; DO NOT EDIT.

package openbanking_common

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

// NewRevokeOpenbankingConsentParams creates a new RevokeOpenbankingConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRevokeOpenbankingConsentParams() *RevokeOpenbankingConsentParams {
	return &RevokeOpenbankingConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRevokeOpenbankingConsentParamsWithTimeout creates a new RevokeOpenbankingConsentParams object
// with the ability to set a timeout on a request.
func NewRevokeOpenbankingConsentParamsWithTimeout(timeout time.Duration) *RevokeOpenbankingConsentParams {
	return &RevokeOpenbankingConsentParams{
		timeout: timeout,
	}
}

// NewRevokeOpenbankingConsentParamsWithContext creates a new RevokeOpenbankingConsentParams object
// with the ability to set a context for a request.
func NewRevokeOpenbankingConsentParamsWithContext(ctx context.Context) *RevokeOpenbankingConsentParams {
	return &RevokeOpenbankingConsentParams{
		Context: ctx,
	}
}

// NewRevokeOpenbankingConsentParamsWithHTTPClient creates a new RevokeOpenbankingConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewRevokeOpenbankingConsentParamsWithHTTPClient(client *http.Client) *RevokeOpenbankingConsentParams {
	return &RevokeOpenbankingConsentParams{
		HTTPClient: client,
	}
}

/* RevokeOpenbankingConsentParams contains all the parameters to send to the API endpoint
   for the revoke openbanking consent operation.

   Typically these are written to a http.Request.
*/
type RevokeOpenbankingConsentParams struct {

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	// ConsentID.
	ConsentID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the revoke openbanking consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeOpenbankingConsentParams) WithDefaults() *RevokeOpenbankingConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the revoke openbanking consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeOpenbankingConsentParams) SetDefaults() {
	var (
		aidDefault = string("default")
	)

	val := RevokeOpenbankingConsentParams{
		Aid: aidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) WithTimeout(timeout time.Duration) *RevokeOpenbankingConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) WithContext(ctx context.Context) *RevokeOpenbankingConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) WithHTTPClient(client *http.Client) *RevokeOpenbankingConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) WithAid(aid string) *RevokeOpenbankingConsentParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) SetAid(aid string) {
	o.Aid = aid
}

// WithConsentID adds the consentID to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) WithConsentID(consentID string) *RevokeOpenbankingConsentParams {
	o.SetConsentID(consentID)
	return o
}

// SetConsentID adds the consentId to the revoke openbanking consent params
func (o *RevokeOpenbankingConsentParams) SetConsentID(consentID string) {
	o.ConsentID = consentID
}

// WriteToRequest writes these params to a swagger request
func (o *RevokeOpenbankingConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param consentID
	if err := r.SetPathParam("consentID", o.ConsentID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
