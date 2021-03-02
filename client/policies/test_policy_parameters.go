// Code generated by go-swagger; DO NOT EDIT.

package policies

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

	"github.com/cloudentity/acp-client-go/models"
)

// NewTestPolicyParams creates a new TestPolicyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewTestPolicyParams() *TestPolicyParams {
	return &TestPolicyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewTestPolicyParamsWithTimeout creates a new TestPolicyParams object
// with the ability to set a timeout on a request.
func NewTestPolicyParamsWithTimeout(timeout time.Duration) *TestPolicyParams {
	return &TestPolicyParams{
		timeout: timeout,
	}
}

// NewTestPolicyParamsWithContext creates a new TestPolicyParams object
// with the ability to set a context for a request.
func NewTestPolicyParamsWithContext(ctx context.Context) *TestPolicyParams {
	return &TestPolicyParams{
		Context: ctx,
	}
}

// NewTestPolicyParamsWithHTTPClient creates a new TestPolicyParams object
// with the ability to set a custom HTTPClient for a request.
func NewTestPolicyParamsWithHTTPClient(client *http.Client) *TestPolicyParams {
	return &TestPolicyParams{
		HTTPClient: client,
	}
}

/* TestPolicyParams contains all the parameters to send to the API endpoint
   for the test policy operation.

   Typically these are written to a http.Request.
*/
type TestPolicyParams struct {

	// TestPolicyRequest.
	TestPolicyRequest *models.TestPolicyRequest

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the test policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TestPolicyParams) WithDefaults() *TestPolicyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the test policy params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TestPolicyParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := TestPolicyParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the test policy params
func (o *TestPolicyParams) WithTimeout(timeout time.Duration) *TestPolicyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the test policy params
func (o *TestPolicyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the test policy params
func (o *TestPolicyParams) WithContext(ctx context.Context) *TestPolicyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the test policy params
func (o *TestPolicyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the test policy params
func (o *TestPolicyParams) WithHTTPClient(client *http.Client) *TestPolicyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the test policy params
func (o *TestPolicyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTestPolicyRequest adds the testPolicyRequest to the test policy params
func (o *TestPolicyParams) WithTestPolicyRequest(testPolicyRequest *models.TestPolicyRequest) *TestPolicyParams {
	o.SetTestPolicyRequest(testPolicyRequest)
	return o
}

// SetTestPolicyRequest adds the testPolicyRequest to the test policy params
func (o *TestPolicyParams) SetTestPolicyRequest(testPolicyRequest *models.TestPolicyRequest) {
	o.TestPolicyRequest = testPolicyRequest
}

// WithTid adds the tid to the test policy params
func (o *TestPolicyParams) WithTid(tid string) *TestPolicyParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the test policy params
func (o *TestPolicyParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *TestPolicyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.TestPolicyRequest != nil {
		if err := r.SetBodyParam(o.TestPolicyRequest); err != nil {
			return err
		}
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
