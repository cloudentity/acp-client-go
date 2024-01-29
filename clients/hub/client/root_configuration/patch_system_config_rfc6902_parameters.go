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

// NewPatchSystemConfigRfc6902Params creates a new PatchSystemConfigRfc6902Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPatchSystemConfigRfc6902Params() *PatchSystemConfigRfc6902Params {
	return &PatchSystemConfigRfc6902Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewPatchSystemConfigRfc6902ParamsWithTimeout creates a new PatchSystemConfigRfc6902Params object
// with the ability to set a timeout on a request.
func NewPatchSystemConfigRfc6902ParamsWithTimeout(timeout time.Duration) *PatchSystemConfigRfc6902Params {
	return &PatchSystemConfigRfc6902Params{
		timeout: timeout,
	}
}

// NewPatchSystemConfigRfc6902ParamsWithContext creates a new PatchSystemConfigRfc6902Params object
// with the ability to set a context for a request.
func NewPatchSystemConfigRfc6902ParamsWithContext(ctx context.Context) *PatchSystemConfigRfc6902Params {
	return &PatchSystemConfigRfc6902Params{
		Context: ctx,
	}
}

// NewPatchSystemConfigRfc6902ParamsWithHTTPClient creates a new PatchSystemConfigRfc6902Params object
// with the ability to set a custom HTTPClient for a request.
func NewPatchSystemConfigRfc6902ParamsWithHTTPClient(client *http.Client) *PatchSystemConfigRfc6902Params {
	return &PatchSystemConfigRfc6902Params{
		HTTPClient: client,
	}
}

/*
PatchSystemConfigRfc6902Params contains all the parameters to send to the API endpoint

	for the patch system config rfc6902 operation.

	Typically these are written to a http.Request.
*/
type PatchSystemConfigRfc6902Params struct {

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

	/* Patch.

	     Patch

	The `patch` parameter is a JSON object that contains an array of RFC-6902 patch operations.
	*/
	Patch models.Rfc6902PatchOperations

	/* Tid.

	   Tenant ID

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the patch system config rfc6902 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchSystemConfigRfc6902Params) WithDefaults() *PatchSystemConfigRfc6902Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the patch system config rfc6902 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PatchSystemConfigRfc6902Params) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := PatchSystemConfigRfc6902Params{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) WithTimeout(timeout time.Duration) *PatchSystemConfigRfc6902Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) WithContext(ctx context.Context) *PatchSystemConfigRfc6902Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) WithHTTPClient(client *http.Client) *PatchSystemConfigRfc6902Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMode adds the mode to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) WithMode(mode *string) *PatchSystemConfigRfc6902Params {
	o.SetMode(mode)
	return o
}

// SetMode adds the mode to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) SetMode(mode *string) {
	o.Mode = mode
}

// WithPatch adds the patch to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) WithPatch(patch models.Rfc6902PatchOperations) *PatchSystemConfigRfc6902Params {
	o.SetPatch(patch)
	return o
}

// SetPatch adds the patch to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) SetPatch(patch models.Rfc6902PatchOperations) {
	o.Patch = patch
}

// WithTid adds the tid to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) WithTid(tid string) *PatchSystemConfigRfc6902Params {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the patch system config rfc6902 params
func (o *PatchSystemConfigRfc6902Params) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *PatchSystemConfigRfc6902Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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
