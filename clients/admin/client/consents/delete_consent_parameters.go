// Code generated by go-swagger; DO NOT EDIT.

package consents

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

// NewDeleteConsentParams creates a new DeleteConsentParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteConsentParams() *DeleteConsentParams {
	return &DeleteConsentParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteConsentParamsWithTimeout creates a new DeleteConsentParams object
// with the ability to set a timeout on a request.
func NewDeleteConsentParamsWithTimeout(timeout time.Duration) *DeleteConsentParams {
	return &DeleteConsentParams{
		timeout: timeout,
	}
}

// NewDeleteConsentParamsWithContext creates a new DeleteConsentParams object
// with the ability to set a context for a request.
func NewDeleteConsentParamsWithContext(ctx context.Context) *DeleteConsentParams {
	return &DeleteConsentParams{
		Context: ctx,
	}
}

// NewDeleteConsentParamsWithHTTPClient creates a new DeleteConsentParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteConsentParamsWithHTTPClient(client *http.Client) *DeleteConsentParams {
	return &DeleteConsentParams{
		HTTPClient: client,
	}
}

/*
DeleteConsentParams contains all the parameters to send to the API endpoint

	for the delete consent operation.

	Typically these are written to a http.Request.
*/
type DeleteConsentParams struct {

	// Consent.
	Consent string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteConsentParams) WithDefaults() *DeleteConsentParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete consent params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteConsentParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete consent params
func (o *DeleteConsentParams) WithTimeout(timeout time.Duration) *DeleteConsentParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete consent params
func (o *DeleteConsentParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete consent params
func (o *DeleteConsentParams) WithContext(ctx context.Context) *DeleteConsentParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete consent params
func (o *DeleteConsentParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete consent params
func (o *DeleteConsentParams) WithHTTPClient(client *http.Client) *DeleteConsentParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete consent params
func (o *DeleteConsentParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsent adds the consent to the delete consent params
func (o *DeleteConsentParams) WithConsent(consent string) *DeleteConsentParams {
	o.SetConsent(consent)
	return o
}

// SetConsent adds the consent to the delete consent params
func (o *DeleteConsentParams) SetConsent(consent string) {
	o.Consent = consent
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteConsentParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param consent
	if err := r.SetPathParam("consent", o.Consent); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
