// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewListClientsParams creates a new ListClientsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListClientsParams() *ListClientsParams {
	return &ListClientsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListClientsParamsWithTimeout creates a new ListClientsParams object
// with the ability to set a timeout on a request.
func NewListClientsParamsWithTimeout(timeout time.Duration) *ListClientsParams {
	return &ListClientsParams{
		timeout: timeout,
	}
}

// NewListClientsParamsWithContext creates a new ListClientsParams object
// with the ability to set a context for a request.
func NewListClientsParamsWithContext(ctx context.Context) *ListClientsParams {
	return &ListClientsParams{
		Context: ctx,
	}
}

// NewListClientsParamsWithHTTPClient creates a new ListClientsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListClientsParamsWithHTTPClient(client *http.Client) *ListClientsParams {
	return &ListClientsParams{
		HTTPClient: client,
	}
}

/* ListClientsParams contains all the parameters to send to the API endpoint
   for the list clients operation.

   Typically these are written to a http.Request.
*/
type ListClientsParams struct {

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

// WithDefaults hydrates default values in the list clients params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsParams) WithDefaults() *ListClientsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list clients params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := ListClientsParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list clients params
func (o *ListClientsParams) WithTimeout(timeout time.Duration) *ListClientsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list clients params
func (o *ListClientsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list clients params
func (o *ListClientsParams) WithContext(ctx context.Context) *ListClientsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list clients params
func (o *ListClientsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list clients params
func (o *ListClientsParams) WithHTTPClient(client *http.Client) *ListClientsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list clients params
func (o *ListClientsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the list clients params
func (o *ListClientsParams) WithAid(aid string) *ListClientsParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the list clients params
func (o *ListClientsParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the list clients params
func (o *ListClientsParams) WithTid(tid string) *ListClientsParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the list clients params
func (o *ListClientsParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ListClientsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
