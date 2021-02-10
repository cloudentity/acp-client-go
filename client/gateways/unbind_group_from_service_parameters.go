// Code generated by go-swagger; DO NOT EDIT.

package gateways

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

// NewUnbindGroupFromServiceParams creates a new UnbindGroupFromServiceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUnbindGroupFromServiceParams() *UnbindGroupFromServiceParams {
	return &UnbindGroupFromServiceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUnbindGroupFromServiceParamsWithTimeout creates a new UnbindGroupFromServiceParams object
// with the ability to set a timeout on a request.
func NewUnbindGroupFromServiceParamsWithTimeout(timeout time.Duration) *UnbindGroupFromServiceParams {
	return &UnbindGroupFromServiceParams{
		timeout: timeout,
	}
}

// NewUnbindGroupFromServiceParamsWithContext creates a new UnbindGroupFromServiceParams object
// with the ability to set a context for a request.
func NewUnbindGroupFromServiceParamsWithContext(ctx context.Context) *UnbindGroupFromServiceParams {
	return &UnbindGroupFromServiceParams{
		Context: ctx,
	}
}

// NewUnbindGroupFromServiceParamsWithHTTPClient creates a new UnbindGroupFromServiceParams object
// with the ability to set a custom HTTPClient for a request.
func NewUnbindGroupFromServiceParamsWithHTTPClient(client *http.Client) *UnbindGroupFromServiceParams {
	return &UnbindGroupFromServiceParams{
		HTTPClient: client,
	}
}

/* UnbindGroupFromServiceParams contains all the parameters to send to the API endpoint
   for the unbind group from service operation.

   Typically these are written to a http.Request.
*/
type UnbindGroupFromServiceParams struct {

	// APIGroup.
	APIGroupID string

	// Gw.
	Gw string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the unbind group from service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UnbindGroupFromServiceParams) WithDefaults() *UnbindGroupFromServiceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the unbind group from service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UnbindGroupFromServiceParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := UnbindGroupFromServiceParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the unbind group from service params
func (o *UnbindGroupFromServiceParams) WithTimeout(timeout time.Duration) *UnbindGroupFromServiceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the unbind group from service params
func (o *UnbindGroupFromServiceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the unbind group from service params
func (o *UnbindGroupFromServiceParams) WithContext(ctx context.Context) *UnbindGroupFromServiceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the unbind group from service params
func (o *UnbindGroupFromServiceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the unbind group from service params
func (o *UnbindGroupFromServiceParams) WithHTTPClient(client *http.Client) *UnbindGroupFromServiceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the unbind group from service params
func (o *UnbindGroupFromServiceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAPIGroupID adds the aPIGroup to the unbind group from service params
func (o *UnbindGroupFromServiceParams) WithAPIGroupID(aPIGroup string) *UnbindGroupFromServiceParams {
	o.SetAPIGroupID(aPIGroup)
	return o
}

// SetAPIGroupID adds the apiGroup to the unbind group from service params
func (o *UnbindGroupFromServiceParams) SetAPIGroupID(aPIGroup string) {
	o.APIGroupID = aPIGroup
}

// WithGw adds the gw to the unbind group from service params
func (o *UnbindGroupFromServiceParams) WithGw(gw string) *UnbindGroupFromServiceParams {
	o.SetGw(gw)
	return o
}

// SetGw adds the gw to the unbind group from service params
func (o *UnbindGroupFromServiceParams) SetGw(gw string) {
	o.Gw = gw
}

// WithTid adds the tid to the unbind group from service params
func (o *UnbindGroupFromServiceParams) WithTid(tid string) *UnbindGroupFromServiceParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the unbind group from service params
func (o *UnbindGroupFromServiceParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UnbindGroupFromServiceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param apiGroup
	if err := r.SetPathParam("apiGroup", o.APIGroupID); err != nil {
		return err
	}

	// path param gw
	if err := r.SetPathParam("gw", o.Gw); err != nil {
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
