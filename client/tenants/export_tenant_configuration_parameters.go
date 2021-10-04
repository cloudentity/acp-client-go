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
)

// NewExportTenantConfigurationParams creates a new ExportTenantConfigurationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExportTenantConfigurationParams() *ExportTenantConfigurationParams {
	return &ExportTenantConfigurationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExportTenantConfigurationParamsWithTimeout creates a new ExportTenantConfigurationParams object
// with the ability to set a timeout on a request.
func NewExportTenantConfigurationParamsWithTimeout(timeout time.Duration) *ExportTenantConfigurationParams {
	return &ExportTenantConfigurationParams{
		timeout: timeout,
	}
}

// NewExportTenantConfigurationParamsWithContext creates a new ExportTenantConfigurationParams object
// with the ability to set a context for a request.
func NewExportTenantConfigurationParamsWithContext(ctx context.Context) *ExportTenantConfigurationParams {
	return &ExportTenantConfigurationParams{
		Context: ctx,
	}
}

// NewExportTenantConfigurationParamsWithHTTPClient creates a new ExportTenantConfigurationParams object
// with the ability to set a custom HTTPClient for a request.
func NewExportTenantConfigurationParamsWithHTTPClient(client *http.Client) *ExportTenantConfigurationParams {
	return &ExportTenantConfigurationParams{
		HTTPClient: client,
	}
}

/* ExportTenantConfigurationParams contains all the parameters to send to the API endpoint
   for the export tenant configuration operation.

   Typically these are written to a http.Request.
*/
type ExportTenantConfigurationParams struct {

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the export tenant configuration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExportTenantConfigurationParams) WithDefaults() *ExportTenantConfigurationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the export tenant configuration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExportTenantConfigurationParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := ExportTenantConfigurationParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the export tenant configuration params
func (o *ExportTenantConfigurationParams) WithTimeout(timeout time.Duration) *ExportTenantConfigurationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the export tenant configuration params
func (o *ExportTenantConfigurationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the export tenant configuration params
func (o *ExportTenantConfigurationParams) WithContext(ctx context.Context) *ExportTenantConfigurationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the export tenant configuration params
func (o *ExportTenantConfigurationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the export tenant configuration params
func (o *ExportTenantConfigurationParams) WithHTTPClient(client *http.Client) *ExportTenantConfigurationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the export tenant configuration params
func (o *ExportTenantConfigurationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTid adds the tid to the export tenant configuration params
func (o *ExportTenantConfigurationParams) WithTid(tid string) *ExportTenantConfigurationParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the export tenant configuration params
func (o *ExportTenantConfigurationParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ExportTenantConfigurationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
