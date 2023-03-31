// Code generated by go-swagger; DO NOT EDIT.

package o_b_u_k

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

// NewOpenbankingDomesticScheduledPaymentConsentIntrospectParams creates a new OpenbankingDomesticScheduledPaymentConsentIntrospectParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOpenbankingDomesticScheduledPaymentConsentIntrospectParams() *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	return &OpenbankingDomesticScheduledPaymentConsentIntrospectParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOpenbankingDomesticScheduledPaymentConsentIntrospectParamsWithTimeout creates a new OpenbankingDomesticScheduledPaymentConsentIntrospectParams object
// with the ability to set a timeout on a request.
func NewOpenbankingDomesticScheduledPaymentConsentIntrospectParamsWithTimeout(timeout time.Duration) *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	return &OpenbankingDomesticScheduledPaymentConsentIntrospectParams{
		timeout: timeout,
	}
}

// NewOpenbankingDomesticScheduledPaymentConsentIntrospectParamsWithContext creates a new OpenbankingDomesticScheduledPaymentConsentIntrospectParams object
// with the ability to set a context for a request.
func NewOpenbankingDomesticScheduledPaymentConsentIntrospectParamsWithContext(ctx context.Context) *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	return &OpenbankingDomesticScheduledPaymentConsentIntrospectParams{
		Context: ctx,
	}
}

// NewOpenbankingDomesticScheduledPaymentConsentIntrospectParamsWithHTTPClient creates a new OpenbankingDomesticScheduledPaymentConsentIntrospectParams object
// with the ability to set a custom HTTPClient for a request.
func NewOpenbankingDomesticScheduledPaymentConsentIntrospectParamsWithHTTPClient(client *http.Client) *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	return &OpenbankingDomesticScheduledPaymentConsentIntrospectParams{
		HTTPClient: client,
	}
}

/*
OpenbankingDomesticScheduledPaymentConsentIntrospectParams contains all the parameters to send to the API endpoint

	for the openbanking domestic scheduled payment consent introspect operation.

	Typically these are written to a http.Request.
*/
type OpenbankingDomesticScheduledPaymentConsentIntrospectParams struct {

	// Token.
	Token *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the openbanking domestic scheduled payment consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) WithDefaults() *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the openbanking domestic scheduled payment consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) WithTimeout(timeout time.Duration) *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) WithContext(ctx context.Context) *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) WithHTTPClient(client *http.Client) *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithToken adds the token to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) WithToken(token *string) *OpenbankingDomesticScheduledPaymentConsentIntrospectParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the openbanking domestic scheduled payment consent introspect params
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) SetToken(token *string) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *OpenbankingDomesticScheduledPaymentConsentIntrospectParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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
