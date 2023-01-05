// Code generated by go-swagger; DO NOT EDIT.

package features

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

	"github.com/cloudentity/acp-client-go/clients/root/models"
)

// NewSetTenantFeatureParams creates a new SetTenantFeatureParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSetTenantFeatureParams() *SetTenantFeatureParams {
	return &SetTenantFeatureParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSetTenantFeatureParamsWithTimeout creates a new SetTenantFeatureParams object
// with the ability to set a timeout on a request.
func NewSetTenantFeatureParamsWithTimeout(timeout time.Duration) *SetTenantFeatureParams {
	return &SetTenantFeatureParams{
		timeout: timeout,
	}
}

// NewSetTenantFeatureParamsWithContext creates a new SetTenantFeatureParams object
// with the ability to set a context for a request.
func NewSetTenantFeatureParamsWithContext(ctx context.Context) *SetTenantFeatureParams {
	return &SetTenantFeatureParams{
		Context: ctx,
	}
}

// NewSetTenantFeatureParamsWithHTTPClient creates a new SetTenantFeatureParams object
// with the ability to set a custom HTTPClient for a request.
func NewSetTenantFeatureParamsWithHTTPClient(client *http.Client) *SetTenantFeatureParams {
	return &SetTenantFeatureParams{
		HTTPClient: client,
	}
}

/*
SetTenantFeatureParams contains all the parameters to send to the API endpoint

	for the set tenant feature operation.

	Typically these are written to a http.Request.
*/
type SetTenantFeatureParams struct {

	// SetTenantFeature.
	SetTenantFeature *models.SetTenantFeature

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the set tenant feature params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetTenantFeatureParams) WithDefaults() *SetTenantFeatureParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the set tenant feature params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetTenantFeatureParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := SetTenantFeatureParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the set tenant feature params
func (o *SetTenantFeatureParams) WithTimeout(timeout time.Duration) *SetTenantFeatureParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the set tenant feature params
func (o *SetTenantFeatureParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the set tenant feature params
func (o *SetTenantFeatureParams) WithContext(ctx context.Context) *SetTenantFeatureParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the set tenant feature params
func (o *SetTenantFeatureParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the set tenant feature params
func (o *SetTenantFeatureParams) WithHTTPClient(client *http.Client) *SetTenantFeatureParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the set tenant feature params
func (o *SetTenantFeatureParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSetTenantFeature adds the setTenantFeature to the set tenant feature params
func (o *SetTenantFeatureParams) WithSetTenantFeature(setTenantFeature *models.SetTenantFeature) *SetTenantFeatureParams {
	o.SetSetTenantFeature(setTenantFeature)
	return o
}

// SetSetTenantFeature adds the setTenantFeature to the set tenant feature params
func (o *SetTenantFeatureParams) SetSetTenantFeature(setTenantFeature *models.SetTenantFeature) {
	o.SetTenantFeature = setTenantFeature
}

// WithTid adds the tid to the set tenant feature params
func (o *SetTenantFeatureParams) WithTid(tid string) *SetTenantFeatureParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the set tenant feature params
func (o *SetTenantFeatureParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *SetTenantFeatureParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.SetTenantFeature != nil {
		if err := r.SetBodyParam(o.SetTenantFeature); err != nil {
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
