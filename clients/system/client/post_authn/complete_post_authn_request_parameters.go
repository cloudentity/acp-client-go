// Code generated by go-swagger; DO NOT EDIT.

package post_authn

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

	"github.com/cloudentity/acp-client-go/clients/system/models"
)

// NewCompletePostAuthnRequestParams creates a new CompletePostAuthnRequestParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCompletePostAuthnRequestParams() *CompletePostAuthnRequestParams {
	return &CompletePostAuthnRequestParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCompletePostAuthnRequestParamsWithTimeout creates a new CompletePostAuthnRequestParams object
// with the ability to set a timeout on a request.
func NewCompletePostAuthnRequestParamsWithTimeout(timeout time.Duration) *CompletePostAuthnRequestParams {
	return &CompletePostAuthnRequestParams{
		timeout: timeout,
	}
}

// NewCompletePostAuthnRequestParamsWithContext creates a new CompletePostAuthnRequestParams object
// with the ability to set a context for a request.
func NewCompletePostAuthnRequestParamsWithContext(ctx context.Context) *CompletePostAuthnRequestParams {
	return &CompletePostAuthnRequestParams{
		Context: ctx,
	}
}

// NewCompletePostAuthnRequestParamsWithHTTPClient creates a new CompletePostAuthnRequestParams object
// with the ability to set a custom HTTPClient for a request.
func NewCompletePostAuthnRequestParamsWithHTTPClient(client *http.Client) *CompletePostAuthnRequestParams {
	return &CompletePostAuthnRequestParams{
		HTTPClient: client,
	}
}

/*
CompletePostAuthnRequestParams contains all the parameters to send to the API endpoint

	for the complete post authn request operation.

	Typically these are written to a http.Request.
*/
type CompletePostAuthnRequestParams struct {

	// CompletePostAuthn.
	CompletePostAuthn *models.CompletePostAuthnSession

	// Login.
	Login string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the complete post authn request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CompletePostAuthnRequestParams) WithDefaults() *CompletePostAuthnRequestParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the complete post authn request params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CompletePostAuthnRequestParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the complete post authn request params
func (o *CompletePostAuthnRequestParams) WithTimeout(timeout time.Duration) *CompletePostAuthnRequestParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the complete post authn request params
func (o *CompletePostAuthnRequestParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the complete post authn request params
func (o *CompletePostAuthnRequestParams) WithContext(ctx context.Context) *CompletePostAuthnRequestParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the complete post authn request params
func (o *CompletePostAuthnRequestParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the complete post authn request params
func (o *CompletePostAuthnRequestParams) WithHTTPClient(client *http.Client) *CompletePostAuthnRequestParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the complete post authn request params
func (o *CompletePostAuthnRequestParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCompletePostAuthn adds the completePostAuthn to the complete post authn request params
func (o *CompletePostAuthnRequestParams) WithCompletePostAuthn(completePostAuthn *models.CompletePostAuthnSession) *CompletePostAuthnRequestParams {
	o.SetCompletePostAuthn(completePostAuthn)
	return o
}

// SetCompletePostAuthn adds the completePostAuthn to the complete post authn request params
func (o *CompletePostAuthnRequestParams) SetCompletePostAuthn(completePostAuthn *models.CompletePostAuthnSession) {
	o.CompletePostAuthn = completePostAuthn
}

// WithLogin adds the login to the complete post authn request params
func (o *CompletePostAuthnRequestParams) WithLogin(login string) *CompletePostAuthnRequestParams {
	o.SetLogin(login)
	return o
}

// SetLogin adds the login to the complete post authn request params
func (o *CompletePostAuthnRequestParams) SetLogin(login string) {
	o.Login = login
}

// WriteToRequest writes these params to a swagger request
func (o *CompletePostAuthnRequestParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.CompletePostAuthn != nil {
		if err := r.SetBodyParam(o.CompletePostAuthn); err != nil {
			return err
		}
	}

	// path param login
	if err := r.SetPathParam("login", o.Login); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
