// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewRotateClientSecretParams creates a new RotateClientSecretParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRotateClientSecretParams() *RotateClientSecretParams {
	return &RotateClientSecretParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRotateClientSecretParamsWithTimeout creates a new RotateClientSecretParams object
// with the ability to set a timeout on a request.
func NewRotateClientSecretParamsWithTimeout(timeout time.Duration) *RotateClientSecretParams {
	return &RotateClientSecretParams{
		timeout: timeout,
	}
}

// NewRotateClientSecretParamsWithContext creates a new RotateClientSecretParams object
// with the ability to set a context for a request.
func NewRotateClientSecretParamsWithContext(ctx context.Context) *RotateClientSecretParams {
	return &RotateClientSecretParams{
		Context: ctx,
	}
}

// NewRotateClientSecretParamsWithHTTPClient creates a new RotateClientSecretParams object
// with the ability to set a custom HTTPClient for a request.
func NewRotateClientSecretParamsWithHTTPClient(client *http.Client) *RotateClientSecretParams {
	return &RotateClientSecretParams{
		HTTPClient: client,
	}
}

/* RotateClientSecretParams contains all the parameters to send to the API endpoint
   for the rotate client secret operation.

   Typically these are written to a http.Request.
*/
type RotateClientSecretParams struct {

	/* AutoRevokeAfter.

	   Auto revoke after

	   Default: "0"
	*/
	AutoRevokeAfter *string

	/* Cid.

	   Client id

	   Default: "default"
	*/
	Cid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the rotate client secret params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RotateClientSecretParams) WithDefaults() *RotateClientSecretParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the rotate client secret params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RotateClientSecretParams) SetDefaults() {
	var (
		autoRevokeAfterDefault = string("0")

		cidDefault = string("default")
	)

	val := RotateClientSecretParams{
		AutoRevokeAfter: &autoRevokeAfterDefault,
		Cid:             cidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the rotate client secret params
func (o *RotateClientSecretParams) WithTimeout(timeout time.Duration) *RotateClientSecretParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the rotate client secret params
func (o *RotateClientSecretParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the rotate client secret params
func (o *RotateClientSecretParams) WithContext(ctx context.Context) *RotateClientSecretParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the rotate client secret params
func (o *RotateClientSecretParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the rotate client secret params
func (o *RotateClientSecretParams) WithHTTPClient(client *http.Client) *RotateClientSecretParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the rotate client secret params
func (o *RotateClientSecretParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAutoRevokeAfter adds the autoRevokeAfter to the rotate client secret params
func (o *RotateClientSecretParams) WithAutoRevokeAfter(autoRevokeAfter *string) *RotateClientSecretParams {
	o.SetAutoRevokeAfter(autoRevokeAfter)
	return o
}

// SetAutoRevokeAfter adds the autoRevokeAfter to the rotate client secret params
func (o *RotateClientSecretParams) SetAutoRevokeAfter(autoRevokeAfter *string) {
	o.AutoRevokeAfter = autoRevokeAfter
}

// WithCid adds the cid to the rotate client secret params
func (o *RotateClientSecretParams) WithCid(cid string) *RotateClientSecretParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the rotate client secret params
func (o *RotateClientSecretParams) SetCid(cid string) {
	o.Cid = cid
}

// WriteToRequest writes these params to a swagger request
func (o *RotateClientSecretParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.AutoRevokeAfter != nil {

		// query param auto_revoke_after
		var qrAutoRevokeAfter string

		if o.AutoRevokeAfter != nil {
			qrAutoRevokeAfter = *o.AutoRevokeAfter
		}
		qAutoRevokeAfter := qrAutoRevokeAfter
		if qAutoRevokeAfter != "" {

			if err := r.SetQueryParam("auto_revoke_after", qAutoRevokeAfter); err != nil {
				return err
			}
		}
	}

	// path param cid
	if err := r.SetPathParam("cid", o.Cid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}