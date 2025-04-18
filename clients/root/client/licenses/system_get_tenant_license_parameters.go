// Code generated by go-swagger; DO NOT EDIT.

package licenses

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

// NewSystemGetTenantLicenseParams creates a new SystemGetTenantLicenseParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSystemGetTenantLicenseParams() *SystemGetTenantLicenseParams {
	return &SystemGetTenantLicenseParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSystemGetTenantLicenseParamsWithTimeout creates a new SystemGetTenantLicenseParams object
// with the ability to set a timeout on a request.
func NewSystemGetTenantLicenseParamsWithTimeout(timeout time.Duration) *SystemGetTenantLicenseParams {
	return &SystemGetTenantLicenseParams{
		timeout: timeout,
	}
}

// NewSystemGetTenantLicenseParamsWithContext creates a new SystemGetTenantLicenseParams object
// with the ability to set a context for a request.
func NewSystemGetTenantLicenseParamsWithContext(ctx context.Context) *SystemGetTenantLicenseParams {
	return &SystemGetTenantLicenseParams{
		Context: ctx,
	}
}

// NewSystemGetTenantLicenseParamsWithHTTPClient creates a new SystemGetTenantLicenseParams object
// with the ability to set a custom HTTPClient for a request.
func NewSystemGetTenantLicenseParamsWithHTTPClient(client *http.Client) *SystemGetTenantLicenseParams {
	return &SystemGetTenantLicenseParams{
		HTTPClient: client,
	}
}

/*
SystemGetTenantLicenseParams contains all the parameters to send to the API endpoint

	for the system get tenant license operation.

	Typically these are written to a http.Request.
*/
type SystemGetTenantLicenseParams struct {

	/* TenantID.

	   Tenant id

	   Default: "default"
	*/
	TenantID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the system get tenant license params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemGetTenantLicenseParams) WithDefaults() *SystemGetTenantLicenseParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the system get tenant license params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemGetTenantLicenseParams) SetDefaults() {
	var (
		tenantIDDefault = string("default")
	)

	val := SystemGetTenantLicenseParams{
		TenantID: tenantIDDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the system get tenant license params
func (o *SystemGetTenantLicenseParams) WithTimeout(timeout time.Duration) *SystemGetTenantLicenseParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the system get tenant license params
func (o *SystemGetTenantLicenseParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the system get tenant license params
func (o *SystemGetTenantLicenseParams) WithContext(ctx context.Context) *SystemGetTenantLicenseParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the system get tenant license params
func (o *SystemGetTenantLicenseParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the system get tenant license params
func (o *SystemGetTenantLicenseParams) WithHTTPClient(client *http.Client) *SystemGetTenantLicenseParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the system get tenant license params
func (o *SystemGetTenantLicenseParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTenantID adds the tenantID to the system get tenant license params
func (o *SystemGetTenantLicenseParams) WithTenantID(tenantID string) *SystemGetTenantLicenseParams {
	o.SetTenantID(tenantID)
	return o
}

// SetTenantID adds the tenantId to the system get tenant license params
func (o *SystemGetTenantLicenseParams) SetTenantID(tenantID string) {
	o.TenantID = tenantID
}

// WriteToRequest writes these params to a swagger request
func (o *SystemGetTenantLicenseParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param tenantID
	if err := r.SetPathParam("tenantID", o.TenantID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
