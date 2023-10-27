// Code generated by go-swagger; DO NOT EDIT.

package workspace_configuration

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

// NewExportWorkspaceConfigParams creates a new ExportWorkspaceConfigParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewExportWorkspaceConfigParams() *ExportWorkspaceConfigParams {
	return &ExportWorkspaceConfigParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewExportWorkspaceConfigParamsWithTimeout creates a new ExportWorkspaceConfigParams object
// with the ability to set a timeout on a request.
func NewExportWorkspaceConfigParamsWithTimeout(timeout time.Duration) *ExportWorkspaceConfigParams {
	return &ExportWorkspaceConfigParams{
		timeout: timeout,
	}
}

// NewExportWorkspaceConfigParamsWithContext creates a new ExportWorkspaceConfigParams object
// with the ability to set a context for a request.
func NewExportWorkspaceConfigParamsWithContext(ctx context.Context) *ExportWorkspaceConfigParams {
	return &ExportWorkspaceConfigParams{
		Context: ctx,
	}
}

// NewExportWorkspaceConfigParamsWithHTTPClient creates a new ExportWorkspaceConfigParams object
// with the ability to set a custom HTTPClient for a request.
func NewExportWorkspaceConfigParamsWithHTTPClient(client *http.Client) *ExportWorkspaceConfigParams {
	return &ExportWorkspaceConfigParams{
		HTTPClient: client,
	}
}

/*
ExportWorkspaceConfigParams contains all the parameters to send to the API endpoint

	for the export workspace config operation.

	Typically these are written to a http.Request.
*/
type ExportWorkspaceConfigParams struct {

	/* Tid.

	   Tenant ID

	   Default: "default"
	*/
	Tid string

	/* Wid.

	   Workspace ID

	   Default: "default"
	*/
	Wid string

	/* WithCredentials.

	   With credentials - if true, credentials are included in the workspace export response
	*/
	WithCredentials *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the export workspace config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExportWorkspaceConfigParams) WithDefaults() *ExportWorkspaceConfigParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the export workspace config params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ExportWorkspaceConfigParams) SetDefaults() {
	var (
		tidDefault = string("default")

		widDefault = string("default")

		withCredentialsDefault = bool(false)
	)

	val := ExportWorkspaceConfigParams{
		Tid:             tidDefault,
		Wid:             widDefault,
		WithCredentials: &withCredentialsDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the export workspace config params
func (o *ExportWorkspaceConfigParams) WithTimeout(timeout time.Duration) *ExportWorkspaceConfigParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the export workspace config params
func (o *ExportWorkspaceConfigParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the export workspace config params
func (o *ExportWorkspaceConfigParams) WithContext(ctx context.Context) *ExportWorkspaceConfigParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the export workspace config params
func (o *ExportWorkspaceConfigParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the export workspace config params
func (o *ExportWorkspaceConfigParams) WithHTTPClient(client *http.Client) *ExportWorkspaceConfigParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the export workspace config params
func (o *ExportWorkspaceConfigParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTid adds the tid to the export workspace config params
func (o *ExportWorkspaceConfigParams) WithTid(tid string) *ExportWorkspaceConfigParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the export workspace config params
func (o *ExportWorkspaceConfigParams) SetTid(tid string) {
	o.Tid = tid
}

// WithWid adds the wid to the export workspace config params
func (o *ExportWorkspaceConfigParams) WithWid(wid string) *ExportWorkspaceConfigParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the export workspace config params
func (o *ExportWorkspaceConfigParams) SetWid(wid string) {
	o.Wid = wid
}

// WithWithCredentials adds the withCredentials to the export workspace config params
func (o *ExportWorkspaceConfigParams) WithWithCredentials(withCredentials *bool) *ExportWorkspaceConfigParams {
	o.SetWithCredentials(withCredentials)
	return o
}

// SetWithCredentials adds the withCredentials to the export workspace config params
func (o *ExportWorkspaceConfigParams) SetWithCredentials(withCredentials *bool) {
	o.WithCredentials = withCredentials
}

// WriteToRequest writes these params to a swagger request
func (o *ExportWorkspaceConfigParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
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
