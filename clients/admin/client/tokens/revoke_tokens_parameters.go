// Code generated by go-swagger; DO NOT EDIT.

package tokens

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

// NewRevokeTokensParams creates a new RevokeTokensParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRevokeTokensParams() *RevokeTokensParams {
	return &RevokeTokensParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRevokeTokensParamsWithTimeout creates a new RevokeTokensParams object
// with the ability to set a timeout on a request.
func NewRevokeTokensParamsWithTimeout(timeout time.Duration) *RevokeTokensParams {
	return &RevokeTokensParams{
		timeout: timeout,
	}
}

// NewRevokeTokensParamsWithContext creates a new RevokeTokensParams object
// with the ability to set a context for a request.
func NewRevokeTokensParamsWithContext(ctx context.Context) *RevokeTokensParams {
	return &RevokeTokensParams{
		Context: ctx,
	}
}

// NewRevokeTokensParamsWithHTTPClient creates a new RevokeTokensParams object
// with the ability to set a custom HTTPClient for a request.
func NewRevokeTokensParamsWithHTTPClient(client *http.Client) *RevokeTokensParams {
	return &RevokeTokensParams{
		HTTPClient: client,
	}
}

/*
RevokeTokensParams contains all the parameters to send to the API endpoint

	for the revoke tokens operation.

	Typically these are written to a http.Request.
*/
type RevokeTokensParams struct {

	// Request.
	Request *models.RevokeTokenRequest

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the revoke tokens params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeTokensParams) WithDefaults() *RevokeTokensParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the revoke tokens params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeTokensParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := RevokeTokensParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the revoke tokens params
func (o *RevokeTokensParams) WithTimeout(timeout time.Duration) *RevokeTokensParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the revoke tokens params
func (o *RevokeTokensParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the revoke tokens params
func (o *RevokeTokensParams) WithContext(ctx context.Context) *RevokeTokensParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the revoke tokens params
func (o *RevokeTokensParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the revoke tokens params
func (o *RevokeTokensParams) WithHTTPClient(client *http.Client) *RevokeTokensParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the revoke tokens params
func (o *RevokeTokensParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the revoke tokens params
func (o *RevokeTokensParams) WithRequest(request *models.RevokeTokenRequest) *RevokeTokensParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the revoke tokens params
func (o *RevokeTokensParams) SetRequest(request *models.RevokeTokenRequest) {
	o.Request = request
}

// WithIfMatch adds the ifMatch to the revoke tokens params
func (o *RevokeTokensParams) WithIfMatch(ifMatch *string) *RevokeTokensParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the revoke tokens params
func (o *RevokeTokensParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the revoke tokens params
func (o *RevokeTokensParams) WithWid(wid string) *RevokeTokensParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the revoke tokens params
func (o *RevokeTokensParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *RevokeTokensParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Request != nil {
		if err := r.SetBodyParam(o.Request); err != nil {
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