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

// NewRotateKeyParams creates a new RotateKeyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRotateKeyParams() *RotateKeyParams {
	return &RotateKeyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRotateKeyParamsWithTimeout creates a new RotateKeyParams object
// with the ability to set a timeout on a request.
func NewRotateKeyParamsWithTimeout(timeout time.Duration) *RotateKeyParams {
	return &RotateKeyParams{
		timeout: timeout,
	}
}

// NewRotateKeyParamsWithContext creates a new RotateKeyParams object
// with the ability to set a context for a request.
func NewRotateKeyParamsWithContext(ctx context.Context) *RotateKeyParams {
	return &RotateKeyParams{
		Context: ctx,
	}
}

// NewRotateKeyParamsWithHTTPClient creates a new RotateKeyParams object
// with the ability to set a custom HTTPClient for a request.
func NewRotateKeyParamsWithHTTPClient(client *http.Client) *RotateKeyParams {
	return &RotateKeyParams{
		HTTPClient: client,
	}
}

/* RotateKeyParams contains all the parameters to send to the API endpoint
   for the rotate key operation.

   Typically these are written to a http.Request.
*/
type RotateKeyParams struct {

	/* KeyType.

	   Key type

	   Default: "rsa"
	*/
	KeyType *string

	/* Use.

	   Key use (sig or enc)

	   Default: "sig"
	*/
	Use *string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the rotate key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RotateKeyParams) WithDefaults() *RotateKeyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the rotate key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RotateKeyParams) SetDefaults() {
	var (
		keyTypeDefault = string("rsa")

		useDefault = string("sig")

		widDefault = string("default")
	)

	val := RotateKeyParams{
		KeyType: &keyTypeDefault,
		Use:     &useDefault,
		Wid:     widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the rotate key params
func (o *RotateKeyParams) WithTimeout(timeout time.Duration) *RotateKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the rotate key params
func (o *RotateKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the rotate key params
func (o *RotateKeyParams) WithContext(ctx context.Context) *RotateKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the rotate key params
func (o *RotateKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the rotate key params
func (o *RotateKeyParams) WithHTTPClient(client *http.Client) *RotateKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the rotate key params
func (o *RotateKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithKeyType adds the keyType to the rotate key params
func (o *RotateKeyParams) WithKeyType(keyType *string) *RotateKeyParams {
	o.SetKeyType(keyType)
	return o
}

// SetKeyType adds the keyType to the rotate key params
func (o *RotateKeyParams) SetKeyType(keyType *string) {
	o.KeyType = keyType
}

// WithUse adds the use to the rotate key params
func (o *RotateKeyParams) WithUse(use *string) *RotateKeyParams {
	o.SetUse(use)
	return o
}

// SetUse adds the use to the rotate key params
func (o *RotateKeyParams) SetUse(use *string) {
	o.Use = use
}

// WithWid adds the wid to the rotate key params
func (o *RotateKeyParams) WithWid(wid string) *RotateKeyParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the rotate key params
func (o *RotateKeyParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *RotateKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.KeyType != nil {

		// query param key_type
		var qrKeyType string

		if o.KeyType != nil {
			qrKeyType = *o.KeyType
		}
		qKeyType := qrKeyType
		if qKeyType != "" {

			if err := r.SetQueryParam("key_type", qKeyType); err != nil {
				return err
			}
		}
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

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
