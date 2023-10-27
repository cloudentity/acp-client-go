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

// NewCreateScriptParams creates a new CreateScriptParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateScriptParams() *CreateScriptParams {
	return &CreateScriptParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateScriptParamsWithTimeout creates a new CreateScriptParams object
// with the ability to set a timeout on a request.
func NewCreateScriptParamsWithTimeout(timeout time.Duration) *CreateScriptParams {
	return &CreateScriptParams{
		timeout: timeout,
	}
}

// NewCreateScriptParamsWithContext creates a new CreateScriptParams object
// with the ability to set a context for a request.
func NewCreateScriptParamsWithContext(ctx context.Context) *CreateScriptParams {
	return &CreateScriptParams{
		Context: ctx,
	}
}

// NewCreateScriptParamsWithHTTPClient creates a new CreateScriptParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateScriptParamsWithHTTPClient(client *http.Client) *CreateScriptParams {
	return &CreateScriptParams{
		HTTPClient: client,
	}
}

/*
CreateScriptParams contains all the parameters to send to the API endpoint

	for the create script operation.

	Typically these are written to a http.Request.
*/
type CreateScriptParams struct {

	// Script.
	Script *models.Script

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   ID of your authorization server (workspace)

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateScriptParams) WithDefaults() *CreateScriptParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create script params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateScriptParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateScriptParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create script params
func (o *CreateScriptParams) WithTimeout(timeout time.Duration) *CreateScriptParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create script params
func (o *CreateScriptParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create script params
func (o *CreateScriptParams) WithContext(ctx context.Context) *CreateScriptParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create script params
func (o *CreateScriptParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create script params
func (o *CreateScriptParams) WithHTTPClient(client *http.Client) *CreateScriptParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create script params
func (o *CreateScriptParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithScript adds the script to the create script params
func (o *CreateScriptParams) WithScript(script *models.Script) *CreateScriptParams {
	o.SetScript(script)
	return o
}

// SetScript adds the script to the create script params
func (o *CreateScriptParams) SetScript(script *models.Script) {
	o.Script = script
}

// WithIfMatch adds the ifMatch to the create script params
func (o *CreateScriptParams) WithIfMatch(ifMatch *string) *CreateScriptParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create script params
func (o *CreateScriptParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the create script params
func (o *CreateScriptParams) WithWid(wid string) *CreateScriptParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create script params
func (o *CreateScriptParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateScriptParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Script != nil {
		if err := r.SetBodyParam(o.Script); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
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
