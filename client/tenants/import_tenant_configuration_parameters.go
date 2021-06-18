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

// NewImportTenantConfigurationParams creates a new ImportTenantConfigurationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewImportTenantConfigurationParams() *ImportTenantConfigurationParams {
	return &ImportTenantConfigurationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewImportTenantConfigurationParamsWithTimeout creates a new ImportTenantConfigurationParams object
// with the ability to set a timeout on a request.
func NewImportTenantConfigurationParamsWithTimeout(timeout time.Duration) *ImportTenantConfigurationParams {
	return &ImportTenantConfigurationParams{
		timeout: timeout,
	}
}

// NewImportTenantConfigurationParamsWithContext creates a new ImportTenantConfigurationParams object
// with the ability to set a context for a request.
func NewImportTenantConfigurationParamsWithContext(ctx context.Context) *ImportTenantConfigurationParams {
	return &ImportTenantConfigurationParams{
		Context: ctx,
	}
}

// NewImportTenantConfigurationParamsWithHTTPClient creates a new ImportTenantConfigurationParams object
// with the ability to set a custom HTTPClient for a request.
func NewImportTenantConfigurationParamsWithHTTPClient(client *http.Client) *ImportTenantConfigurationParams {
	return &ImportTenantConfigurationParams{
		HTTPClient: client,
	}
}

/* ImportTenantConfigurationParams contains all the parameters to send to the API endpoint
   for the import tenant configuration operation.

   Typically these are written to a http.Request.
*/
type ImportTenantConfigurationParams struct {

	// TenantDump.
	TenantDump *models.TenantDump

	// Mode.
	//
	// Format: insertMode
	Mode *string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the import tenant configuration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ImportTenantConfigurationParams) WithDefaults() *ImportTenantConfigurationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the import tenant configuration params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ImportTenantConfigurationParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := ImportTenantConfigurationParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the import tenant configuration params
func (o *ImportTenantConfigurationParams) WithTimeout(timeout time.Duration) *ImportTenantConfigurationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the import tenant configuration params
func (o *ImportTenantConfigurationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the import tenant configuration params
func (o *ImportTenantConfigurationParams) WithContext(ctx context.Context) *ImportTenantConfigurationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the import tenant configuration params
func (o *ImportTenantConfigurationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the import tenant configuration params
func (o *ImportTenantConfigurationParams) WithHTTPClient(client *http.Client) *ImportTenantConfigurationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the import tenant configuration params
func (o *ImportTenantConfigurationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTenantDump adds the tenantDump to the import tenant configuration params
func (o *ImportTenantConfigurationParams) WithTenantDump(tenantDump *models.TenantDump) *ImportTenantConfigurationParams {
	o.SetTenantDump(tenantDump)
	return o
}

// SetTenantDump adds the tenantDump to the import tenant configuration params
func (o *ImportTenantConfigurationParams) SetTenantDump(tenantDump *models.TenantDump) {
	o.TenantDump = tenantDump
}

// WithMode adds the mode to the import tenant configuration params
func (o *ImportTenantConfigurationParams) WithMode(mode *string) *ImportTenantConfigurationParams {
	o.SetMode(mode)
	return o
}

// SetMode adds the mode to the import tenant configuration params
func (o *ImportTenantConfigurationParams) SetMode(mode *string) {
	o.Mode = mode
}

// WithTid adds the tid to the import tenant configuration params
func (o *ImportTenantConfigurationParams) WithTid(tid string) *ImportTenantConfigurationParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the import tenant configuration params
func (o *ImportTenantConfigurationParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ImportTenantConfigurationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.TenantDump != nil {
		if err := r.SetBodyParam(o.TenantDump); err != nil {
			return err
		}
	}

	if o.Mode != nil {

		// query param mode
		var qrMode string

		if o.Mode != nil {
			qrMode = *o.Mode
		}
		qMode := qrMode
		if qMode != "" {

			if err := r.SetQueryParam("mode", qMode); err != nil {
				return err
			}
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
