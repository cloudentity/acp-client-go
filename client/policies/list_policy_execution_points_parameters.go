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
)

// NewListPolicyExecutionPointsParams creates a new ListPolicyExecutionPointsParams object
// with the default values initialized.
func NewListPolicyExecutionPointsParams() *ListPolicyExecutionPointsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListPolicyExecutionPointsParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewListPolicyExecutionPointsParamsWithTimeout creates a new ListPolicyExecutionPointsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListPolicyExecutionPointsParamsWithTimeout(timeout time.Duration) *ListPolicyExecutionPointsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListPolicyExecutionPointsParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: timeout,
	}
}

// NewListPolicyExecutionPointsParamsWithContext creates a new ListPolicyExecutionPointsParams object
// with the default values initialized, and the ability to set a context for a request
func NewListPolicyExecutionPointsParamsWithContext(ctx context.Context) *ListPolicyExecutionPointsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListPolicyExecutionPointsParams{
		Aid: aidDefault,
		Tid: tidDefault,

		Context: ctx,
	}
}

// NewListPolicyExecutionPointsParamsWithHTTPClient creates a new ListPolicyExecutionPointsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListPolicyExecutionPointsParamsWithHTTPClient(client *http.Client) *ListPolicyExecutionPointsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListPolicyExecutionPointsParams{
		Aid:        aidDefault,
		Tid:        tidDefault,
		HTTPClient: client,
	}
}

/*ListPolicyExecutionPointsParams contains all the parameters to send to the API endpoint
for the list policy execution points operation typically these are written to a http.Request
*/
type ListPolicyExecutionPointsParams struct {

	/*Aid
	  Authorization server id

	*/
	Aid string
	/*Tid
	  Tenant id

	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) WithTimeout(timeout time.Duration) *ListPolicyExecutionPointsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) WithContext(ctx context.Context) *ListPolicyExecutionPointsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) WithHTTPClient(client *http.Client) *ListPolicyExecutionPointsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) WithAid(aid string) *ListPolicyExecutionPointsParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) WithTid(tid string) *ListPolicyExecutionPointsParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the list policy execution points params
func (o *ListPolicyExecutionPointsParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ListPolicyExecutionPointsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
