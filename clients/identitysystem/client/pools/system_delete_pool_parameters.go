// Code generated by go-swagger; DO NOT EDIT.

package pools

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

// NewSystemDeletePoolParams creates a new SystemDeletePoolParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSystemDeletePoolParams() *SystemDeletePoolParams {
	return &SystemDeletePoolParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSystemDeletePoolParamsWithTimeout creates a new SystemDeletePoolParams object
// with the ability to set a timeout on a request.
func NewSystemDeletePoolParamsWithTimeout(timeout time.Duration) *SystemDeletePoolParams {
	return &SystemDeletePoolParams{
		timeout: timeout,
	}
}

// NewSystemDeletePoolParamsWithContext creates a new SystemDeletePoolParams object
// with the ability to set a context for a request.
func NewSystemDeletePoolParamsWithContext(ctx context.Context) *SystemDeletePoolParams {
	return &SystemDeletePoolParams{
		Context: ctx,
	}
}

// NewSystemDeletePoolParamsWithHTTPClient creates a new SystemDeletePoolParams object
// with the ability to set a custom HTTPClient for a request.
func NewSystemDeletePoolParamsWithHTTPClient(client *http.Client) *SystemDeletePoolParams {
	return &SystemDeletePoolParams{
		HTTPClient: client,
	}
}

/*
SystemDeletePoolParams contains all the parameters to send to the API endpoint

	for the system delete pool operation.

	Typically these are written to a http.Request.
*/
type SystemDeletePoolParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// IPID.
	IPID string

	/* WithIdp.

	   With idp
	*/
	WithIdp *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the system delete pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemDeletePoolParams) WithDefaults() *SystemDeletePoolParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the system delete pool params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SystemDeletePoolParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the system delete pool params
func (o *SystemDeletePoolParams) WithTimeout(timeout time.Duration) *SystemDeletePoolParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the system delete pool params
func (o *SystemDeletePoolParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the system delete pool params
func (o *SystemDeletePoolParams) WithContext(ctx context.Context) *SystemDeletePoolParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the system delete pool params
func (o *SystemDeletePoolParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the system delete pool params
func (o *SystemDeletePoolParams) WithHTTPClient(client *http.Client) *SystemDeletePoolParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the system delete pool params
func (o *SystemDeletePoolParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the system delete pool params
func (o *SystemDeletePoolParams) WithIfMatch(ifMatch *string) *SystemDeletePoolParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the system delete pool params
func (o *SystemDeletePoolParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIPID adds the iPID to the system delete pool params
func (o *SystemDeletePoolParams) WithIPID(iPID string) *SystemDeletePoolParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the system delete pool params
func (o *SystemDeletePoolParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithWithIdp adds the withIdp to the system delete pool params
func (o *SystemDeletePoolParams) WithWithIdp(withIdp *bool) *SystemDeletePoolParams {
	o.SetWithIdp(withIdp)
	return o
}

// SetWithIdp adds the withIdp to the system delete pool params
func (o *SystemDeletePoolParams) SetWithIdp(withIdp *bool) {
	o.WithIdp = withIdp
}

// WriteToRequest writes these params to a swagger request
func (o *SystemDeletePoolParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	if o.WithIdp != nil {

		// query param with_idp
		var qrWithIdp bool

		if o.WithIdp != nil {
			qrWithIdp = *o.WithIdp
		}
		qWithIdp := swag.FormatBool(qrWithIdp)
		if qWithIdp != "" {

			if err := r.SetQueryParam("with_idp", qWithIdp); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}