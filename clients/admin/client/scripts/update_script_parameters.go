// Code generated by go-swagger; DO NOT EDIT.

package scripts

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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// NewUpdateScriptParams creates a new UpdateScriptParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateScriptParams() *UpdateScriptParams {
	return &UpdateScriptParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateScriptParamsWithTimeout creates a new UpdateScriptParams object
// with the ability to set a timeout on a request.
func NewUpdateScriptParamsWithTimeout(timeout time.Duration) *UpdateScriptParams {
	return &UpdateScriptParams{
		timeout: timeout,
	}
}

// NewUpdateScriptParamsWithContext creates a new UpdateScriptParams object
// with the ability to set a context for a request.
func NewUpdateScriptParamsWithContext(ctx context.Context) *UpdateScriptParams {
	return &UpdateScriptParams{
		Context: ctx,
	}
}

// NewUpdateScriptParamsWithHTTPClient creates a new UpdateScriptParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateScriptParamsWithHTTPClient(client *http.Client) *UpdateScriptParams {
	return &UpdateScriptParams{
		HTTPClient: client,
	}
}

/*
UpdateScriptParams contains all the parameters to send to the API endpoint

	for the update script operation.

	Typically these are written to a http.Request.
*/
type UpdateScriptParams struct {

	// ScriptBody.
	ScriptBody *models.Script

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Script.

	   ID of the script to be updated
	*/
	Script string

	/* Wid.

	   ID of your authorization server (workspace)

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateScriptParams) WithDefaults() *UpdateScriptParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateScriptParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := UpdateScriptParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update script params
func (o *UpdateScriptParams) WithTimeout(timeout time.Duration) *UpdateScriptParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update script params
func (o *UpdateScriptParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update script params
func (o *UpdateScriptParams) WithContext(ctx context.Context) *UpdateScriptParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update script params
func (o *UpdateScriptParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update script params
func (o *UpdateScriptParams) WithHTTPClient(client *http.Client) *UpdateScriptParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update script params
func (o *UpdateScriptParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithScriptBody adds the scriptBody to the update script params
func (o *UpdateScriptParams) WithScriptBody(scriptBody *models.Script) *UpdateScriptParams {
	o.SetScriptBody(scriptBody)
	return o
}

// SetScriptBody adds the scriptBody to the update script params
func (o *UpdateScriptParams) SetScriptBody(scriptBody *models.Script) {
	o.ScriptBody = scriptBody
}

// WithIfMatch adds the ifMatch to the update script params
func (o *UpdateScriptParams) WithIfMatch(ifMatch *string) *UpdateScriptParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update script params
func (o *UpdateScriptParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithScript adds the script to the update script params
func (o *UpdateScriptParams) WithScript(script string) *UpdateScriptParams {
	o.SetScript(script)
	return o
}

// SetScript adds the script to the update script params
func (o *UpdateScriptParams) SetScript(script string) {
	o.Script = script
}

// WithWid adds the wid to the update script params
func (o *UpdateScriptParams) WithWid(wid string) *UpdateScriptParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the update script params
func (o *UpdateScriptParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateScriptParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ScriptBody != nil {
		if err := r.SetBodyParam(o.ScriptBody); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param script
	if err := r.SetPathParam("script", o.Script); err != nil {
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
