// Code generated by go-swagger; DO NOT EDIT.

package system

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

// NewGatewayExchangeParams creates a new GatewayExchangeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGatewayExchangeParams() *GatewayExchangeParams {
	return &GatewayExchangeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGatewayExchangeParamsWithTimeout creates a new GatewayExchangeParams object
// with the ability to set a timeout on a request.
func NewGatewayExchangeParamsWithTimeout(timeout time.Duration) *GatewayExchangeParams {
	return &GatewayExchangeParams{
		timeout: timeout,
	}
}

// NewGatewayExchangeParamsWithContext creates a new GatewayExchangeParams object
// with the ability to set a context for a request.
func NewGatewayExchangeParamsWithContext(ctx context.Context) *GatewayExchangeParams {
	return &GatewayExchangeParams{
		Context: ctx,
	}
}

// NewGatewayExchangeParamsWithHTTPClient creates a new GatewayExchangeParams object
// with the ability to set a custom HTTPClient for a request.
func NewGatewayExchangeParamsWithHTTPClient(client *http.Client) *GatewayExchangeParams {
	return &GatewayExchangeParams{
		HTTPClient: client,
	}
}

/*
GatewayExchangeParams contains all the parameters to send to the API endpoint

	for the gateway exchange operation.

	Typically these are written to a http.Request.
*/
type GatewayExchangeParams struct {

	// RequestScopes.
	//
	// Default: "original_token"
	RequestScopes *string

	// SubjectToken.
	SubjectToken *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the gateway exchange params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GatewayExchangeParams) WithDefaults() *GatewayExchangeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the gateway exchange params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GatewayExchangeParams) SetDefaults() {
	var (
		requestScopesDefault = string("original_token")
	)

	val := GatewayExchangeParams{
		RequestScopes: &requestScopesDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the gateway exchange params
func (o *GatewayExchangeParams) WithTimeout(timeout time.Duration) *GatewayExchangeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the gateway exchange params
func (o *GatewayExchangeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the gateway exchange params
func (o *GatewayExchangeParams) WithContext(ctx context.Context) *GatewayExchangeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the gateway exchange params
func (o *GatewayExchangeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the gateway exchange params
func (o *GatewayExchangeParams) WithHTTPClient(client *http.Client) *GatewayExchangeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the gateway exchange params
func (o *GatewayExchangeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequestScopes adds the requestScopes to the gateway exchange params
func (o *GatewayExchangeParams) WithRequestScopes(requestScopes *string) *GatewayExchangeParams {
	o.SetRequestScopes(requestScopes)
	return o
}

// SetRequestScopes adds the requestScopes to the gateway exchange params
func (o *GatewayExchangeParams) SetRequestScopes(requestScopes *string) {
	o.RequestScopes = requestScopes
}

// WithSubjectToken adds the subjectToken to the gateway exchange params
func (o *GatewayExchangeParams) WithSubjectToken(subjectToken *string) *GatewayExchangeParams {
	o.SetSubjectToken(subjectToken)
	return o
}

// SetSubjectToken adds the subjectToken to the gateway exchange params
func (o *GatewayExchangeParams) SetSubjectToken(subjectToken *string) {
	o.SubjectToken = subjectToken
}

// WriteToRequest writes these params to a swagger request
func (o *GatewayExchangeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.RequestScopes != nil {

		// form param request_scopes
		var frRequestScopes string
		if o.RequestScopes != nil {
			frRequestScopes = *o.RequestScopes
		}
		fRequestScopes := frRequestScopes
		if fRequestScopes != "" {
			if err := r.SetFormParam("request_scopes", fRequestScopes); err != nil {
				return err
			}
		}
	}

	if o.SubjectToken != nil {

		// form param subject_token
		var frSubjectToken string
		if o.SubjectToken != nil {
			frSubjectToken = *o.SubjectToken
		}
		fSubjectToken := frSubjectToken
		if fSubjectToken != "" {
			if err := r.SetFormParam("subject_token", fSubjectToken); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
