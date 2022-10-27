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
)

// NewOpenbankingInternationalPaymentConsentIntrospectParams creates a new OpenbankingInternationalPaymentConsentIntrospectParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOpenbankingInternationalPaymentConsentIntrospectParams() *OpenbankingInternationalPaymentConsentIntrospectParams {
	return &OpenbankingInternationalPaymentConsentIntrospectParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOpenbankingInternationalPaymentConsentIntrospectParamsWithTimeout creates a new OpenbankingInternationalPaymentConsentIntrospectParams object
// with the ability to set a timeout on a request.
func NewOpenbankingInternationalPaymentConsentIntrospectParamsWithTimeout(timeout time.Duration) *OpenbankingInternationalPaymentConsentIntrospectParams {
	return &OpenbankingInternationalPaymentConsentIntrospectParams{
		timeout: timeout,
	}
}

// NewOpenbankingInternationalPaymentConsentIntrospectParamsWithContext creates a new OpenbankingInternationalPaymentConsentIntrospectParams object
// with the ability to set a context for a request.
func NewOpenbankingInternationalPaymentConsentIntrospectParamsWithContext(ctx context.Context) *OpenbankingInternationalPaymentConsentIntrospectParams {
	return &OpenbankingInternationalPaymentConsentIntrospectParams{
		Context: ctx,
	}
}

// NewOpenbankingInternationalPaymentConsentIntrospectParamsWithHTTPClient creates a new OpenbankingInternationalPaymentConsentIntrospectParams object
// with the ability to set a custom HTTPClient for a request.
func NewOpenbankingInternationalPaymentConsentIntrospectParamsWithHTTPClient(client *http.Client) *OpenbankingInternationalPaymentConsentIntrospectParams {
	return &OpenbankingInternationalPaymentConsentIntrospectParams{
		HTTPClient: client,
	}
}

/*
OpenbankingInternationalPaymentConsentIntrospectParams contains all the parameters to send to the API endpoint

	for the openbanking international payment consent introspect operation.

	Typically these are written to a http.Request.
*/
type OpenbankingInternationalPaymentConsentIntrospectParams struct {

	// Token.
	Token *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the openbanking international payment consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) WithDefaults() *OpenbankingInternationalPaymentConsentIntrospectParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the openbanking international payment consent introspect params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) WithTimeout(timeout time.Duration) *OpenbankingInternationalPaymentConsentIntrospectParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) WithContext(ctx context.Context) *OpenbankingInternationalPaymentConsentIntrospectParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) WithHTTPClient(client *http.Client) *OpenbankingInternationalPaymentConsentIntrospectParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithToken adds the token to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) WithToken(token *string) *OpenbankingInternationalPaymentConsentIntrospectParams {
	o.SetToken(token)
	return o
}

// SetToken adds the token to the openbanking international payment consent introspect params
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) SetToken(token *string) {
	o.Token = token
}

// WriteToRequest writes these params to a swagger request
func (o *OpenbankingInternationalPaymentConsentIntrospectParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
