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

	"github.com/cloudentity/acp-client-go/clients/hub/models"
)

// NewPatchWorkspaceConfigRfc7396Params creates a new PatchWorkspaceConfigRfc7396Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPatchWorkspaceConfigRfc7396Params() *PatchWorkspaceConfigRfc7396Params {
	return &PatchWorkspaceConfigRfc7396Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewPatchWorkspaceConfigRfc7396ParamsWithTimeout creates a new PatchWorkspaceConfigRfc7396Params object
// with the ability to set a timeout on a request.
func NewPatchWorkspaceConfigRfc7396ParamsWithTimeout(timeout time.Duration) *PatchWorkspaceConfigRfc7396Params {
	return &PatchWorkspaceConfigRfc7396Params{
		timeout: timeout,
	}
}

// NewPatchWorkspaceConfigRfc7396ParamsWithContext creates a new PatchWorkspaceConfigRfc7396Params object
// with the ability to set a context for a request.
func NewPatchWorkspaceConfigRfc7396ParamsWithContext(ctx context.Context) *PatchWorkspaceConfigRfc7396Params {
	return &PatchWorkspaceConfigRfc7396Params{
		Context: ctx,
	}
}

// NewPatchWorkspaceConfigRfc7396ParamsWithHTTPClient creates a new PatchWorkspaceConfigRfc7396Params object
// with the ability to set a custom HTTPClient for a request.
func NewPatchWorkspaceConfigRfc7396ParamsWithHTTPClient(client *http.Client) *PatchWorkspaceConfigRfc7396Params {
	return &PatchWorkspaceConfigRfc7396Params{
		HTTPClient: client,
	}
}

/*
PatchWorkspaceConfigRfc7396Params contains all the parameters to send to the API endpoint

	for the patch workspace config rfc7396 operation.

	Typically these are written to a http.Request.
*/
type PatchWorkspaceConfigRfc7396Params struct {

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

	// Patch.
	Patch models.Rfc7396PatchOperation

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

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the patch workspace config rfc7396 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchWorkspaceConfigRfc7396Params) WithDefaults() *PatchWorkspaceConfigRfc7396Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the patch workspace config rfc7396 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchWorkspaceConfigRfc7396Params) SetDefaults() {
	var (
		dryRunDefault = string("false")

		tidDefault = string("default")

		widDefault = string("default")
	)

	val := PatchWorkspaceConfigRfc7396Params{
		DryRun: &dryRunDefault,
		Tid:    tidDefault,
		Wid:    widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithTimeout(timeout time.Duration) *PatchWorkspaceConfigRfc7396Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithContext(ctx context.Context) *PatchWorkspaceConfigRfc7396Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithHTTPClient(client *http.Client) *PatchWorkspaceConfigRfc7396Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithDryRun adds the dryRun to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithDryRun(dryRun *string) *PatchWorkspaceConfigRfc7396Params {
	o.SetDryRun(dryRun)
	return o
}

// SetDryRun adds the dryRun to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetDryRun(dryRun *string) {
	o.DryRun = dryRun
}

// WithMode adds the mode to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithMode(mode *string) *PatchWorkspaceConfigRfc7396Params {
	o.SetMode(mode)
	return o
}

// SetMode adds the mode to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetMode(mode *string) {
	o.Mode = mode
}

// WithPatch adds the patch to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithPatch(patch models.Rfc7396PatchOperation) *PatchWorkspaceConfigRfc7396Params {
	o.SetPatch(patch)
	return o
}

// SetPatch adds the patch to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetPatch(patch models.Rfc7396PatchOperation) {
	o.Patch = patch
}

// WithTid adds the tid to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithTid(tid string) *PatchWorkspaceConfigRfc7396Params {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetTid(tid string) {
	o.Tid = tid
}

// WithWid adds the wid to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) WithWid(wid string) *PatchWorkspaceConfigRfc7396Params {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the patch workspace config rfc7396 params
func (o *PatchWorkspaceConfigRfc7396Params) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *PatchWorkspaceConfigRfc7396Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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
	if o.Patch != nil {
		if err := r.SetBodyParam(o.Patch); err != nil {
			return err
		}
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
