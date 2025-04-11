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

	"github.com/cloudentity/acp-client-go/clients/identitysystem/models"
)

// NewVerifyAuthenticationCodeParams creates a new VerifyAuthenticationCodeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewVerifyAuthenticationCodeParams() *VerifyAuthenticationCodeParams {
	return &VerifyAuthenticationCodeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewVerifyAuthenticationCodeParamsWithTimeout creates a new VerifyAuthenticationCodeParams object
// with the ability to set a timeout on a request.
func NewVerifyAuthenticationCodeParamsWithTimeout(timeout time.Duration) *VerifyAuthenticationCodeParams {
	return &VerifyAuthenticationCodeParams{
		timeout: timeout,
	}
}

// NewVerifyAuthenticationCodeParamsWithContext creates a new VerifyAuthenticationCodeParams object
// with the ability to set a context for a request.
func NewVerifyAuthenticationCodeParamsWithContext(ctx context.Context) *VerifyAuthenticationCodeParams {
	return &VerifyAuthenticationCodeParams{
		Context: ctx,
	}
}

// NewVerifyAuthenticationCodeParamsWithHTTPClient creates a new VerifyAuthenticationCodeParams object
// with the ability to set a custom HTTPClient for a request.
func NewVerifyAuthenticationCodeParamsWithHTTPClient(client *http.Client) *VerifyAuthenticationCodeParams {
	return &VerifyAuthenticationCodeParams{
		HTTPClient: client,
	}
}

/*
VerifyAuthenticationCodeParams contains all the parameters to send to the API endpoint

	for the verify authentication code operation.

	Typically these are written to a http.Request.
*/
type VerifyAuthenticationCodeParams struct {

	// VerifyAuthenticationCode.
	VerifyAuthenticationCode *models.BaseVerifyOTP

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the verify authentication code params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *VerifyAuthenticationCodeParams) WithDefaults() *VerifyAuthenticationCodeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the verify authentication code params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *VerifyAuthenticationCodeParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) WithTimeout(timeout time.Duration) *VerifyAuthenticationCodeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) WithContext(ctx context.Context) *VerifyAuthenticationCodeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) WithHTTPClient(client *http.Client) *VerifyAuthenticationCodeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithVerifyAuthenticationCode adds the verifyAuthenticationCode to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) WithVerifyAuthenticationCode(verifyAuthenticationCode *models.BaseVerifyOTP) *VerifyAuthenticationCodeParams {
	o.SetVerifyAuthenticationCode(verifyAuthenticationCode)
	return o
}

// SetVerifyAuthenticationCode adds the verifyAuthenticationCode to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) SetVerifyAuthenticationCode(verifyAuthenticationCode *models.BaseVerifyOTP) {
	o.VerifyAuthenticationCode = verifyAuthenticationCode
}

// WithIfMatch adds the ifMatch to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) WithIfMatch(ifMatch *string) *VerifyAuthenticationCodeParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) WithIPID(iPID string) *VerifyAuthenticationCodeParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the verify authentication code params
func (o *VerifyAuthenticationCodeParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WriteToRequest writes these params to a swagger request
func (o *VerifyAuthenticationCodeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.VerifyAuthenticationCode != nil {
		if err := r.SetBodyParam(o.VerifyAuthenticationCode); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
