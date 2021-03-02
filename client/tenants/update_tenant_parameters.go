// Code generated by go-swagger; DO NOT EDIT.

package tenants

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

// NewUpdateTenantParams creates a new UpdateTenantParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateTenantParams() *UpdateTenantParams {
	return &UpdateTenantParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateTenantParamsWithTimeout creates a new UpdateTenantParams object
// with the ability to set a timeout on a request.
func NewUpdateTenantParamsWithTimeout(timeout time.Duration) *UpdateTenantParams {
	return &UpdateTenantParams{
		timeout: timeout,
	}
}

// NewUpdateTenantParamsWithContext creates a new UpdateTenantParams object
// with the ability to set a context for a request.
func NewUpdateTenantParamsWithContext(ctx context.Context) *UpdateTenantParams {
	return &UpdateTenantParams{
		Context: ctx,
	}
}

// NewUpdateTenantParamsWithHTTPClient creates a new UpdateTenantParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateTenantParamsWithHTTPClient(client *http.Client) *UpdateTenantParams {
	return &UpdateTenantParams{
		HTTPClient: client,
	}
}

/* UpdateTenantParams contains all the parameters to send to the API endpoint
   for the update tenant operation.

   Typically these are written to a http.Request.
*/
type UpdateTenantParams struct {

	// Tenant.
	Tenant *models.Tenant

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update tenant params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateTenantParams) WithDefaults() *UpdateTenantParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update tenant params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateTenantParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := UpdateTenantParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update tenant params
func (o *UpdateTenantParams) WithTimeout(timeout time.Duration) *UpdateTenantParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update tenant params
func (o *UpdateTenantParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update tenant params
func (o *UpdateTenantParams) WithContext(ctx context.Context) *UpdateTenantParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update tenant params
func (o *UpdateTenantParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update tenant params
func (o *UpdateTenantParams) WithHTTPClient(client *http.Client) *UpdateTenantParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update tenant params
func (o *UpdateTenantParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTenant adds the tenant to the update tenant params
func (o *UpdateTenantParams) WithTenant(tenant *models.Tenant) *UpdateTenantParams {
	o.SetTenant(tenant)
	return o
}

// SetTenant adds the tenant to the update tenant params
func (o *UpdateTenantParams) SetTenant(tenant *models.Tenant) {
	o.Tenant = tenant
}

// WithTid adds the tid to the update tenant params
func (o *UpdateTenantParams) WithTid(tid string) *UpdateTenantParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the update tenant params
func (o *UpdateTenantParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateTenantParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Tenant != nil {
		if err := r.SetBodyParam(o.Tenant); err != nil {
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
