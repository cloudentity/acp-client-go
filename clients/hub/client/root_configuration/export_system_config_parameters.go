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
	"github.com/go-openapi/swag"
)

// NewExportSystemConfigParams creates a new ExportSystemConfigParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExportSystemConfigParams() *ExportSystemConfigParams {
	return &ExportSystemConfigParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExportSystemConfigParamsWithTimeout creates a new ExportSystemConfigParams object
// with the ability to set a timeout on a request.
func NewExportSystemConfigParamsWithTimeout(timeout time.Duration) *ExportSystemConfigParams {
	return &ExportSystemConfigParams{
		timeout: timeout,
	}
}

// NewExportSystemConfigParamsWithContext creates a new ExportSystemConfigParams object
// with the ability to set a context for a request.
func NewExportSystemConfigParamsWithContext(ctx context.Context) *ExportSystemConfigParams {
	return &ExportSystemConfigParams{
		Context: ctx,
	}
}

// NewExportSystemConfigParamsWithHTTPClient creates a new ExportSystemConfigParams object
// with the ability to set a custom HTTPClient for a request.
func NewExportSystemConfigParamsWithHTTPClient(client *http.Client) *ExportSystemConfigParams {
	return &ExportSystemConfigParams{
		HTTPClient: client,
	}
}

/*
ExportSystemConfigParams contains all the parameters to send to the API endpoint

	for the export system config operation.

	Typically these are written to a http.Request.
*/
type ExportSystemConfigParams struct {

	/* Tid.

	   Tenant ID

	   Default: "default"
	*/
	Tid string

	/* WithCredentials.

	   With credentials - if true, credentials are included in the tenant export response
	*/
	WithCredentials *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the export system config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExportSystemConfigParams) WithDefaults() *ExportSystemConfigParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the export system config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExportSystemConfigParams) SetDefaults() {
	var (
		tidDefault = string("default")

		withCredentialsDefault = bool(false)
	)

	val := ExportSystemConfigParams{
		Tid:             tidDefault,
		WithCredentials: &withCredentialsDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the export system config params
func (o *ExportSystemConfigParams) WithTimeout(timeout time.Duration) *ExportSystemConfigParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the export system config params
func (o *ExportSystemConfigParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the export system config params
func (o *ExportSystemConfigParams) WithContext(ctx context.Context) *ExportSystemConfigParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the export system config params
func (o *ExportSystemConfigParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the export system config params
func (o *ExportSystemConfigParams) WithHTTPClient(client *http.Client) *ExportSystemConfigParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the export system config params
func (o *ExportSystemConfigParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTid adds the tid to the export system config params
func (o *ExportSystemConfigParams) WithTid(tid string) *ExportSystemConfigParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the export system config params
func (o *ExportSystemConfigParams) SetTid(tid string) {
	o.Tid = tid
}

// WithWithCredentials adds the withCredentials to the export system config params
func (o *ExportSystemConfigParams) WithWithCredentials(withCredentials *bool) *ExportSystemConfigParams {
	o.SetWithCredentials(withCredentials)
	return o
}

// SetWithCredentials adds the withCredentials to the export system config params
func (o *ExportSystemConfigParams) SetWithCredentials(withCredentials *bool) {
	o.WithCredentials = withCredentials
}

// WriteToRequest writes these params to a swagger request
func (o *ExportSystemConfigParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param tid
	qrTid := o.Tid
	qTid := qrTid
	if qTid != "" {

		if err := r.SetQueryParam("tid", qTid); err != nil {
			return err
		}
	}

	if o.WithCredentials != nil {

		// query param with_credentials
		var qrWithCredentials bool

		if o.WithCredentials != nil {
			qrWithCredentials = *o.WithCredentials
		}
		qWithCredentials := swag.FormatBool(qrWithCredentials)
		if qWithCredentials != "" {

			if err := r.SetQueryParam("with_credentials", qWithCredentials); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}