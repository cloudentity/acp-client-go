// Code generated by go-swagger; DO NOT EDIT.

package idps

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

// NewListIDPsParams creates a new ListIDPsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListIDPsParams() *ListIDPsParams {
	return &ListIDPsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListIDPsParamsWithTimeout creates a new ListIDPsParams object
// with the ability to set a timeout on a request.
func NewListIDPsParamsWithTimeout(timeout time.Duration) *ListIDPsParams {
	return &ListIDPsParams{
		timeout: timeout,
	}
}

// NewListIDPsParamsWithContext creates a new ListIDPsParams object
// with the ability to set a context for a request.
func NewListIDPsParamsWithContext(ctx context.Context) *ListIDPsParams {
	return &ListIDPsParams{
		Context: ctx,
	}
}

// NewListIDPsParamsWithHTTPClient creates a new ListIDPsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListIDPsParamsWithHTTPClient(client *http.Client) *ListIDPsParams {
	return &ListIDPsParams{
		HTTPClient: client,
	}
}

/* ListIDPsParams contains all the parameters to send to the API endpoint
   for the list ID ps operation.

   Typically these are written to a http.Request.
*/
type ListIDPsParams struct {

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list ID ps params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListIDPsParams) WithDefaults() *ListIDPsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list ID ps params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListIDPsParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := ListIDPsParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list ID ps params
func (o *ListIDPsParams) WithTimeout(timeout time.Duration) *ListIDPsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list ID ps params
func (o *ListIDPsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list ID ps params
func (o *ListIDPsParams) WithContext(ctx context.Context) *ListIDPsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list ID ps params
func (o *ListIDPsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list ID ps params
func (o *ListIDPsParams) WithHTTPClient(client *http.Client) *ListIDPsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list ID ps params
func (o *ListIDPsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the list ID ps params
func (o *ListIDPsParams) WithAid(aid string) *ListIDPsParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the list ID ps params
func (o *ListIDPsParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the list ID ps params
func (o *ListIDPsParams) WithTid(tid string) *ListIDPsParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the list ID ps params
func (o *ListIDPsParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ListIDPsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
