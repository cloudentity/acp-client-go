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

	"github.com/cloudentity/acp-client-go/models"
)

// NewBindGroupToServiceParams creates a new BindGroupToServiceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBindGroupToServiceParams() *BindGroupToServiceParams {
	return &BindGroupToServiceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBindGroupToServiceParamsWithTimeout creates a new BindGroupToServiceParams object
// with the ability to set a timeout on a request.
func NewBindGroupToServiceParamsWithTimeout(timeout time.Duration) *BindGroupToServiceParams {
	return &BindGroupToServiceParams{
		timeout: timeout,
	}
}

// NewBindGroupToServiceParamsWithContext creates a new BindGroupToServiceParams object
// with the ability to set a context for a request.
func NewBindGroupToServiceParamsWithContext(ctx context.Context) *BindGroupToServiceParams {
	return &BindGroupToServiceParams{
		Context: ctx,
	}
}

// NewBindGroupToServiceParamsWithHTTPClient creates a new BindGroupToServiceParams object
// with the ability to set a custom HTTPClient for a request.
func NewBindGroupToServiceParamsWithHTTPClient(client *http.Client) *BindGroupToServiceParams {
	return &BindGroupToServiceParams{
		HTTPClient: client,
	}
}

/* BindGroupToServiceParams contains all the parameters to send to the API endpoint
   for the bind group to service operation.

   Typically these are written to a http.Request.
*/
type BindGroupToServiceParams struct {

	// BindGroupToServiceRequest.
	BindGroupToServiceRequest *models.BindGroupToServiceRequest

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

// WithDefaults hydrates default values in the bind group to service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BindGroupToServiceParams) WithDefaults() *BindGroupToServiceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the bind group to service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BindGroupToServiceParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := BindGroupToServiceParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the bind group to service params
func (o *BindGroupToServiceParams) WithTimeout(timeout time.Duration) *BindGroupToServiceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the bind group to service params
func (o *BindGroupToServiceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the bind group to service params
func (o *BindGroupToServiceParams) WithContext(ctx context.Context) *BindGroupToServiceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the bind group to service params
func (o *BindGroupToServiceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the bind group to service params
func (o *BindGroupToServiceParams) WithHTTPClient(client *http.Client) *BindGroupToServiceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the bind group to service params
func (o *BindGroupToServiceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBindGroupToServiceRequest adds the bindGroupToServiceRequest to the bind group to service params
func (o *BindGroupToServiceParams) WithBindGroupToServiceRequest(bindGroupToServiceRequest *models.BindGroupToServiceRequest) *BindGroupToServiceParams {
	o.SetBindGroupToServiceRequest(bindGroupToServiceRequest)
	return o
}

// SetBindGroupToServiceRequest adds the bindGroupToServiceRequest to the bind group to service params
func (o *BindGroupToServiceParams) SetBindGroupToServiceRequest(bindGroupToServiceRequest *models.BindGroupToServiceRequest) {
	o.BindGroupToServiceRequest = bindGroupToServiceRequest
}

// WithAPIGroupID adds the aPIGroup to the bind group to service params
func (o *BindGroupToServiceParams) WithAPIGroupID(aPIGroup string) *BindGroupToServiceParams {
	o.SetAPIGroupID(aPIGroup)
	return o
}

// SetAPIGroupID adds the apiGroup to the bind group to service params
func (o *BindGroupToServiceParams) SetAPIGroupID(aPIGroup string) {
	o.APIGroupID = aPIGroup
}

// WithGw adds the gw to the bind group to service params
func (o *BindGroupToServiceParams) WithGw(gw string) *BindGroupToServiceParams {
	o.SetGw(gw)
	return o
}

// SetGw adds the gw to the bind group to service params
func (o *BindGroupToServiceParams) SetGw(gw string) {
	o.Gw = gw
}

// WithTid adds the tid to the bind group to service params
func (o *BindGroupToServiceParams) WithTid(tid string) *BindGroupToServiceParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the bind group to service params
func (o *BindGroupToServiceParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *BindGroupToServiceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.BindGroupToServiceRequest != nil {
		if err := r.SetBodyParam(o.BindGroupToServiceRequest); err != nil {
			return err
		}
	}

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
