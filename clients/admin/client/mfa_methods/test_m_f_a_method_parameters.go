// Code generated by go-swagger; DO NOT EDIT.

package mfa_methods

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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// NewTestMFAMethodParams creates a new TestMFAMethodParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewTestMFAMethodParams() *TestMFAMethodParams {
	return &TestMFAMethodParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewTestMFAMethodParamsWithTimeout creates a new TestMFAMethodParams object
// with the ability to set a timeout on a request.
func NewTestMFAMethodParamsWithTimeout(timeout time.Duration) *TestMFAMethodParams {
	return &TestMFAMethodParams{
		timeout: timeout,
	}
}

// NewTestMFAMethodParamsWithContext creates a new TestMFAMethodParams object
// with the ability to set a context for a request.
func NewTestMFAMethodParamsWithContext(ctx context.Context) *TestMFAMethodParams {
	return &TestMFAMethodParams{
		Context: ctx,
	}
}

// NewTestMFAMethodParamsWithHTTPClient creates a new TestMFAMethodParams object
// with the ability to set a custom HTTPClient for a request.
func NewTestMFAMethodParamsWithHTTPClient(client *http.Client) *TestMFAMethodParams {
	return &TestMFAMethodParams{
		HTTPClient: client,
	}
}

/*
TestMFAMethodParams contains all the parameters to send to the API endpoint

	for the test m f a method operation.

	Typically these are written to a http.Request.
*/
type TestMFAMethodParams struct {

	// MFAMethodTest.
	MFAMethodTest *models.TestMFAMethodRequest

	/* MfaID.

	   MFA id
	*/
	MfaID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the test m f a method params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TestMFAMethodParams) WithDefaults() *TestMFAMethodParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the test m f a method params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TestMFAMethodParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the test m f a method params
func (o *TestMFAMethodParams) WithTimeout(timeout time.Duration) *TestMFAMethodParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the test m f a method params
func (o *TestMFAMethodParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the test m f a method params
func (o *TestMFAMethodParams) WithContext(ctx context.Context) *TestMFAMethodParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the test m f a method params
func (o *TestMFAMethodParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the test m f a method params
func (o *TestMFAMethodParams) WithHTTPClient(client *http.Client) *TestMFAMethodParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the test m f a method params
func (o *TestMFAMethodParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMFAMethodTest adds the mFAMethodTest to the test m f a method params
func (o *TestMFAMethodParams) WithMFAMethodTest(mFAMethodTest *models.TestMFAMethodRequest) *TestMFAMethodParams {
	o.SetMFAMethodTest(mFAMethodTest)
	return o
}

// SetMFAMethodTest adds the mFAMethodTest to the test m f a method params
func (o *TestMFAMethodParams) SetMFAMethodTest(mFAMethodTest *models.TestMFAMethodRequest) {
	o.MFAMethodTest = mFAMethodTest
}

// WithMfaID adds the mfaID to the test m f a method params
func (o *TestMFAMethodParams) WithMfaID(mfaID string) *TestMFAMethodParams {
	o.SetMfaID(mfaID)
	return o
}

// SetMfaID adds the mfaId to the test m f a method params
func (o *TestMFAMethodParams) SetMfaID(mfaID string) {
	o.MfaID = mfaID
}

// WriteToRequest writes these params to a swagger request
func (o *TestMFAMethodParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.MFAMethodTest != nil {
		if err := r.SetBodyParam(o.MFAMethodTest); err != nil {
			return err
		}
	}

	// path param mfaID
	if err := r.SetPathParam("mfaID", o.MfaID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
