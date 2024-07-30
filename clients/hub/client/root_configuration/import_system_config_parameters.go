// Code generated by go-swagger; DO NOT EDIT.

package root_configuration

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

	"github.com/cloudentity/acp-client-go/clients/hub/models"
)

// NewImportSystemConfigParams creates a new ImportSystemConfigParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewImportSystemConfigParams() *ImportSystemConfigParams {
	return &ImportSystemConfigParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewImportSystemConfigParamsWithTimeout creates a new ImportSystemConfigParams object
// with the ability to set a timeout on a request.
func NewImportSystemConfigParamsWithTimeout(timeout time.Duration) *ImportSystemConfigParams {
	return &ImportSystemConfigParams{
		timeout: timeout,
	}
}

// NewImportSystemConfigParamsWithContext creates a new ImportSystemConfigParams object
// with the ability to set a context for a request.
func NewImportSystemConfigParamsWithContext(ctx context.Context) *ImportSystemConfigParams {
	return &ImportSystemConfigParams{
		Context: ctx,
	}
}

// NewImportSystemConfigParamsWithHTTPClient creates a new ImportSystemConfigParams object
// with the ability to set a custom HTTPClient for a request.
func NewImportSystemConfigParamsWithHTTPClient(client *http.Client) *ImportSystemConfigParams {
	return &ImportSystemConfigParams{
		HTTPClient: client,
	}
}

/*
ImportSystemConfigParams contains all the parameters to send to the API endpoint

	for the import system config operation.

	Typically these are written to a http.Request.
*/
type ImportSystemConfigParams struct {

	// Config.
	Config *models.TreeTenant

	/* DryRun.

	   Dry Run

	   Default: "false"
	*/
	DryRun *string

	/* Mode.

	     Insert mode

	Defines what happens in case of patched configuration import conflicts.

	The `mode` parameter defines
	what happens if there are any conflicts when importing your configuration. For example, if a
	client already exists within Cloudentity and you are trying to import a
	configuration that also has a client with this ID, there are the following ways
	Cloudentity can handle the request:

	`mode` set to `ignore`, Cloudentity ignores the changes that come from your configuration import.

	`mode` set to `fail`, Cloudentity stops processing the import and returns an error.

	`mode` set to `update`, Cloudentity updates the value from the previous configuration with the value
	provided in the request.

	     Format: insertMode
	*/
	Mode *string

	/* Tid.

	   Tenant ID

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the import system config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ImportSystemConfigParams) WithDefaults() *ImportSystemConfigParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the import system config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ImportSystemConfigParams) SetDefaults() {
	var (
		dryRunDefault = string("false")

		tidDefault = string("default")
	)

	val := ImportSystemConfigParams{
		DryRun: &dryRunDefault,
		Tid:    tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the import system config params
func (o *ImportSystemConfigParams) WithTimeout(timeout time.Duration) *ImportSystemConfigParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the import system config params
func (o *ImportSystemConfigParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the import system config params
func (o *ImportSystemConfigParams) WithContext(ctx context.Context) *ImportSystemConfigParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the import system config params
func (o *ImportSystemConfigParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the import system config params
func (o *ImportSystemConfigParams) WithHTTPClient(client *http.Client) *ImportSystemConfigParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the import system config params
func (o *ImportSystemConfigParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConfig adds the config to the import system config params
func (o *ImportSystemConfigParams) WithConfig(config *models.TreeTenant) *ImportSystemConfigParams {
	o.SetConfig(config)
	return o
}

// SetConfig adds the config to the import system config params
func (o *ImportSystemConfigParams) SetConfig(config *models.TreeTenant) {
	o.Config = config
}

// WithDryRun adds the dryRun to the import system config params
func (o *ImportSystemConfigParams) WithDryRun(dryRun *string) *ImportSystemConfigParams {
	o.SetDryRun(dryRun)
	return o
}

// SetDryRun adds the dryRun to the import system config params
func (o *ImportSystemConfigParams) SetDryRun(dryRun *string) {
	o.DryRun = dryRun
}

// WithMode adds the mode to the import system config params
func (o *ImportSystemConfigParams) WithMode(mode *string) *ImportSystemConfigParams {
	o.SetMode(mode)
	return o
}

// SetMode adds the mode to the import system config params
func (o *ImportSystemConfigParams) SetMode(mode *string) {
	o.Mode = mode
}

// WithTid adds the tid to the import system config params
func (o *ImportSystemConfigParams) WithTid(tid string) *ImportSystemConfigParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the import system config params
func (o *ImportSystemConfigParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *ImportSystemConfigParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Config != nil {
		if err := r.SetBodyParam(o.Config); err != nil {
			return err
		}
	}

	if o.DryRun != nil {

		// query param dry_run
		var qrDryRun string

		if o.DryRun != nil {
			qrDryRun = *o.DryRun
		}
		qDryRun := qrDryRun
		if qDryRun != "" {

			if err := r.SetQueryParam("dry_run", qDryRun); err != nil {
				return err
			}
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

	// query param tid
	qrTid := o.Tid
	qTid := qrTid
	if qTid != "" {

		if err := r.SetQueryParam("tid", qTid); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
