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
)

// NewOpenbankingDomesticPaymentConsentIntrospectParams creates a new OpenbankingDomesticPaymentConsentIntrospectParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOpenbankingDomesticPaymentConsentIntrospectParams() *OpenbankingDomesticPaymentConsentIntrospectParams {
	return &OpenbankingDomesticPaymentConsentIntrospectParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOpenbankingDomesticPaymentConsentIntrospectParamsWithTimeout creates a new OpenbankingDomesticPaymentConsentIntrospectParams object
// with the ability to set a timeout on a request.
func NewOpenbankingDomesticPaymentConsentIntrospectParamsWithTimeout(timeout time.Duration) *OpenbankingDomesticPaymentConsentIntrospectParams {
	return &OpenbankingDomesticPaymentConsentIntrospectParams{
		timeout: timeout,
	}
}

// NewOpenbankingDomesticPaymentConsentIntrospectParamsWithContext creates a new OpenbankingDomesticPaymentConsentIntrospectParams object
// with the ability to set a context for a request.
func NewOpenbankingDomesticPaymentConsentIntrospectParamsWithContext(ctx context.Context) *OpenbankingDomesticPaymentConsentIntrospectParams {
	return &OpenbankingDomesticPaymentConsentIntrospectParams{
		Context: ctx,
	}
}

// NewOpenbankingDomesticPaymentConsentIntrospectParamsWithHTTPClient creates a new OpenbankingDomesticPaymentConsentIntrospectParams object
// with the ability to set a custom HTTPClient for a request.
func NewOpenbankingDomesticPaymentConsentIntrospectParamsWithHTTPClient(client *http.Client) *OpenbankingDomesticPaymentConsentIntrospectParams {
	return &OpenbankingDomesticPaymentConsentIntrospectParams{
		HTTPClient: client,
	}
}

/* OpenbankingDomesticPaymentConsentIntrospectParams contains all the parameters to send to the API endpoint
   for the openbanking domestic payment consent introspect operation.

   Typically these are written to a http.Request.
*/
type OpenbankingDomesticPaymentConsentIntrospectParams struct {

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	// Token.
	Token *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the openbanking domestic payment consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WithDefaults() *OpenbankingDomesticPaymentConsentIntrospectParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the openbanking domestic payment consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := OpenbankingDomesticPaymentConsentIntrospectParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WithTimeout(timeout time.Duration) *OpenbankingDomesticPaymentConsentIntrospectParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WithContext(ctx context.Context) *OpenbankingDomesticPaymentConsentIntrospectParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WithHTTPClient(client *http.Client) *OpenbankingDomesticPaymentConsentIntrospectParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WithAid(aid string) *OpenbankingDomesticPaymentConsentIntrospectParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WithTid(tid string) *OpenbankingDomesticPaymentConsentIntrospectParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) SetTid(tid string) {
	o.Tid = tid
}

// WithToken adds the token to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WithToken(token *string) *OpenbankingDomesticPaymentConsentIntrospectParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the openbanking domestic payment consent introspect params
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) SetToken(token *string) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *OpenbankingDomesticPaymentConsentIntrospectParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if o.Token != nil {

		// form param token
		var frToken string
		if o.Token != nil {
			frToken = *o.Token
		}
		fToken := frToken
		if fToken != "" {
			if err := r.SetFormParam("token", fToken); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
