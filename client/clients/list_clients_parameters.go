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

// NewListClientsParams creates a new ListClientsParams object
// with the default values initialized.
func NewListClientsParams() *ListClientsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListClientsParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewListClientsParamsWithTimeout creates a new ListClientsParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewListClientsParamsWithTimeout(timeout time.Duration) *ListClientsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListClientsParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: timeout,
	}
}

// NewListClientsParamsWithContext creates a new ListClientsParams object
// with the default values initialized, and the ability to set a context for a request
func NewListClientsParamsWithContext(ctx context.Context) *ListClientsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListClientsParams{
		Aid: aidDefault,
		Tid: tidDefault,

		Context: ctx,
	}
}

// NewListClientsParamsWithHTTPClient creates a new ListClientsParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewListClientsParamsWithHTTPClient(client *http.Client) *ListClientsParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &ListClientsParams{
		Aid:        aidDefault,
		Tid:        tidDefault,
		HTTPClient: client,
	}
}

/*ListClientsParams contains all the parameters to send to the API endpoint
for the list clients operation typically these are written to a http.Request
*/
type ListClientsParams struct {

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
