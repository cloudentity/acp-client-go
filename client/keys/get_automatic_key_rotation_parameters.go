// Code generated by go-swagger; DO NOT EDIT.

package keys

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

// NewGetAutomaticKeyRotationParams creates a new GetAutomaticKeyRotationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAutomaticKeyRotationParams() *GetAutomaticKeyRotationParams {
	return &GetAutomaticKeyRotationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAutomaticKeyRotationParamsWithTimeout creates a new GetAutomaticKeyRotationParams object
// with the ability to set a timeout on a request.
func NewGetAutomaticKeyRotationParamsWithTimeout(timeout time.Duration) *GetAutomaticKeyRotationParams {
	return &GetAutomaticKeyRotationParams{
		timeout: timeout,
	}
}

// NewGetAutomaticKeyRotationParamsWithContext creates a new GetAutomaticKeyRotationParams object
// with the ability to set a context for a request.
func NewGetAutomaticKeyRotationParamsWithContext(ctx context.Context) *GetAutomaticKeyRotationParams {
	return &GetAutomaticKeyRotationParams{
		Context: ctx,
	}
}

// NewGetAutomaticKeyRotationParamsWithHTTPClient creates a new GetAutomaticKeyRotationParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAutomaticKeyRotationParamsWithHTTPClient(client *http.Client) *GetAutomaticKeyRotationParams {
	return &GetAutomaticKeyRotationParams{
		HTTPClient: client,
	}
}

/* GetAutomaticKeyRotationParams contains all the parameters to send to the API endpoint
   for the get automatic key rotation operation.

   Typically these are written to a http.Request.
*/
type GetAutomaticKeyRotationParams struct {

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	/* Use.

	   Key use (sig or enc)

	   Default: "sig"
	*/
	Use *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get automatic key rotation params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAutomaticKeyRotationParams) WithDefaults() *GetAutomaticKeyRotationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get automatic key rotation params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAutomaticKeyRotationParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")

		useDefault = string("sig")
	)

	val := GetAutomaticKeyRotationParams{
		Aid: aidDefault,
		Tid: tidDefault,
		Use: &useDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) WithTimeout(timeout time.Duration) *GetAutomaticKeyRotationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) WithContext(ctx context.Context) *GetAutomaticKeyRotationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) WithHTTPClient(client *http.Client) *GetAutomaticKeyRotationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) WithAid(aid string) *GetAutomaticKeyRotationParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) WithTid(tid string) *GetAutomaticKeyRotationParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) SetTid(tid string) {
	o.Tid = tid
}

// WithUse adds the use to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) WithUse(use *string) *GetAutomaticKeyRotationParams {
	o.SetUse(use)
	return o
}

// SetUse adds the use to the get automatic key rotation params
func (o *GetAutomaticKeyRotationParams) SetUse(use *string) {
	o.Use = use
}

// WriteToRequest writes these params to a swagger request
func (o *GetAutomaticKeyRotationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if o.Use != nil {

		// query param use
		var qrUse string

		if o.Use != nil {
			qrUse = *o.Use
		}
		qUse := qrUse
		if qUse != "" {

			if err := r.SetQueryParam("use", qUse); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}