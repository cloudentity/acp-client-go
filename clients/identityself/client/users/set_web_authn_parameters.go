// Code generated by go-swagger; DO NOT EDIT.

package users

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

	"github.com/cloudentity/acp-client-go/clients/identityself/models"
)

// NewSetWebAuthnParams creates a new SetWebAuthnParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSetWebAuthnParams() *SetWebAuthnParams {
	return &SetWebAuthnParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSetWebAuthnParamsWithTimeout creates a new SetWebAuthnParams object
// with the ability to set a timeout on a request.
func NewSetWebAuthnParamsWithTimeout(timeout time.Duration) *SetWebAuthnParams {
	return &SetWebAuthnParams{
		timeout: timeout,
	}
}

// NewSetWebAuthnParamsWithContext creates a new SetWebAuthnParams object
// with the ability to set a context for a request.
func NewSetWebAuthnParamsWithContext(ctx context.Context) *SetWebAuthnParams {
	return &SetWebAuthnParams{
		Context: ctx,
	}
}

// NewSetWebAuthnParamsWithHTTPClient creates a new SetWebAuthnParams object
// with the ability to set a custom HTTPClient for a request.
func NewSetWebAuthnParamsWithHTTPClient(client *http.Client) *SetWebAuthnParams {
	return &SetWebAuthnParams{
		HTTPClient: client,
	}
}

/*
SetWebAuthnParams contains all the parameters to send to the API endpoint

	for the set web authn operation.

	Typically these are written to a http.Request.
*/
type SetWebAuthnParams struct {

	// SetWebAuthnSecret.
	SetWebAuthnSecret *models.SetWebAuthn

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the set web authn params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetWebAuthnParams) WithDefaults() *SetWebAuthnParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the set web authn params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetWebAuthnParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the set web authn params
func (o *SetWebAuthnParams) WithTimeout(timeout time.Duration) *SetWebAuthnParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the set web authn params
func (o *SetWebAuthnParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the set web authn params
func (o *SetWebAuthnParams) WithContext(ctx context.Context) *SetWebAuthnParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the set web authn params
func (o *SetWebAuthnParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the set web authn params
func (o *SetWebAuthnParams) WithHTTPClient(client *http.Client) *SetWebAuthnParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the set web authn params
func (o *SetWebAuthnParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSetWebAuthnSecret adds the setWebAuthnSecret to the set web authn params
func (o *SetWebAuthnParams) WithSetWebAuthnSecret(setWebAuthnSecret *models.SetWebAuthn) *SetWebAuthnParams {
	o.SetSetWebAuthnSecret(setWebAuthnSecret)
	return o
}

// SetSetWebAuthnSecret adds the setWebAuthnSecret to the set web authn params
func (o *SetWebAuthnParams) SetSetWebAuthnSecret(setWebAuthnSecret *models.SetWebAuthn) {
	o.SetWebAuthnSecret = setWebAuthnSecret
}

// WriteToRequest writes these params to a swagger request
func (o *SetWebAuthnParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.SetWebAuthnSecret != nil {
		if err := r.SetBodyParam(o.SetWebAuthnSecret); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
