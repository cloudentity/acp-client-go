// Code generated by go-swagger; DO NOT EDIT.

package scripts

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

// NewDeleteScriptParams creates a new DeleteScriptParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteScriptParams() *DeleteScriptParams {
	return &DeleteScriptParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteScriptParamsWithTimeout creates a new DeleteScriptParams object
// with the ability to set a timeout on a request.
func NewDeleteScriptParamsWithTimeout(timeout time.Duration) *DeleteScriptParams {
	return &DeleteScriptParams{
		timeout: timeout,
	}
}

// NewDeleteScriptParamsWithContext creates a new DeleteScriptParams object
// with the ability to set a context for a request.
func NewDeleteScriptParamsWithContext(ctx context.Context) *DeleteScriptParams {
	return &DeleteScriptParams{
		Context: ctx,
	}
}

// NewDeleteScriptParamsWithHTTPClient creates a new DeleteScriptParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteScriptParamsWithHTTPClient(client *http.Client) *DeleteScriptParams {
	return &DeleteScriptParams{
		HTTPClient: client,
	}
}

/* DeleteScriptParams contains all the parameters to send to the API endpoint
   for the delete script operation.

   Typically these are written to a http.Request.
*/
type DeleteScriptParams struct {

	/* Aid.

	   ID of your authorization server (workspace)

	   Default: "default"
	*/
	Aid string

	/* Script.

	   ID of the script to be deleted
	*/
	Script string

	/* Tid.

	   ID of your tenant

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteScriptParams) WithDefaults() *DeleteScriptParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteScriptParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := DeleteScriptParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the delete script params
func (o *DeleteScriptParams) WithTimeout(timeout time.Duration) *DeleteScriptParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete script params
func (o *DeleteScriptParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete script params
func (o *DeleteScriptParams) WithContext(ctx context.Context) *DeleteScriptParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete script params
func (o *DeleteScriptParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete script params
func (o *DeleteScriptParams) WithHTTPClient(client *http.Client) *DeleteScriptParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete script params
func (o *DeleteScriptParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the delete script params
func (o *DeleteScriptParams) WithAid(aid string) *DeleteScriptParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the delete script params
func (o *DeleteScriptParams) SetAid(aid string) {
	o.Aid = aid
}

// WithScript adds the script to the delete script params
func (o *DeleteScriptParams) WithScript(script string) *DeleteScriptParams {
	o.SetScript(script)
	return o
}

// SetScript adds the script to the delete script params
func (o *DeleteScriptParams) SetScript(script string) {
	o.Script = script
}

// WithTid adds the tid to the delete script params
func (o *DeleteScriptParams) WithTid(tid string) *DeleteScriptParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the delete script params
func (o *DeleteScriptParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteScriptParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param script
	if err := r.SetPathParam("script", o.Script); err != nil {
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
