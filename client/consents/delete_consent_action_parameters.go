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

// NewDeleteConsentActionParams creates a new DeleteConsentActionParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteConsentActionParams() *DeleteConsentActionParams {
	return &DeleteConsentActionParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteConsentActionParamsWithTimeout creates a new DeleteConsentActionParams object
// with the ability to set a timeout on a request.
func NewDeleteConsentActionParamsWithTimeout(timeout time.Duration) *DeleteConsentActionParams {
	return &DeleteConsentActionParams{
		timeout: timeout,
	}
}

// NewDeleteConsentActionParamsWithContext creates a new DeleteConsentActionParams object
// with the ability to set a context for a request.
func NewDeleteConsentActionParamsWithContext(ctx context.Context) *DeleteConsentActionParams {
	return &DeleteConsentActionParams{
		Context: ctx,
	}
}

// NewDeleteConsentActionParamsWithHTTPClient creates a new DeleteConsentActionParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteConsentActionParamsWithHTTPClient(client *http.Client) *DeleteConsentActionParams {
	return &DeleteConsentActionParams{
		HTTPClient: client,
	}
}

/* DeleteConsentActionParams contains all the parameters to send to the API endpoint
   for the delete consent action operation.

   Typically these are written to a http.Request.
*/
type DeleteConsentActionParams struct {

	// Action.
	Action string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete consent action params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteConsentActionParams) WithDefaults() *DeleteConsentActionParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete consent action params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteConsentActionParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := DeleteConsentActionParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the delete consent action params
func (o *DeleteConsentActionParams) WithTimeout(timeout time.Duration) *DeleteConsentActionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete consent action params
func (o *DeleteConsentActionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete consent action params
func (o *DeleteConsentActionParams) WithContext(ctx context.Context) *DeleteConsentActionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete consent action params
func (o *DeleteConsentActionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete consent action params
func (o *DeleteConsentActionParams) WithHTTPClient(client *http.Client) *DeleteConsentActionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete consent action params
func (o *DeleteConsentActionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAction adds the action to the delete consent action params
func (o *DeleteConsentActionParams) WithAction(action string) *DeleteConsentActionParams {
	o.SetAction(action)
	return o
}

// SetAction adds the action to the delete consent action params
func (o *DeleteConsentActionParams) SetAction(action string) {
	o.Action = action
}

// WithTid adds the tid to the delete consent action params
func (o *DeleteConsentActionParams) WithTid(tid string) *DeleteConsentActionParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the delete consent action params
func (o *DeleteConsentActionParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteConsentActionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param action
	if err := r.SetPathParam("action", o.Action); err != nil {
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
