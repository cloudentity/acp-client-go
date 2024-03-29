// Code generated by go-swagger; DO NOT EDIT.

package custom_apps

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

// NewGetCustomAppParams creates a new GetCustomAppParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCustomAppParams() *GetCustomAppParams {
	return &GetCustomAppParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCustomAppParamsWithTimeout creates a new GetCustomAppParams object
// with the ability to set a timeout on a request.
func NewGetCustomAppParamsWithTimeout(timeout time.Duration) *GetCustomAppParams {
	return &GetCustomAppParams{
		timeout: timeout,
	}
}

// NewGetCustomAppParamsWithContext creates a new GetCustomAppParams object
// with the ability to set a context for a request.
func NewGetCustomAppParamsWithContext(ctx context.Context) *GetCustomAppParams {
	return &GetCustomAppParams{
		Context: ctx,
	}
}

// NewGetCustomAppParamsWithHTTPClient creates a new GetCustomAppParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCustomAppParamsWithHTTPClient(client *http.Client) *GetCustomAppParams {
	return &GetCustomAppParams{
		HTTPClient: client,
	}
}

/*
GetCustomAppParams contains all the parameters to send to the API endpoint

	for the get custom app operation.

	Typically these are written to a http.Request.
*/
type GetCustomAppParams struct {

	/* CustomAppID.

	   CustomApp ID
	*/
	CustomAppID string

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Authorization server id
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get custom app params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCustomAppParams) WithDefaults() *GetCustomAppParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get custom app params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCustomAppParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get custom app params
func (o *GetCustomAppParams) WithTimeout(timeout time.Duration) *GetCustomAppParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get custom app params
func (o *GetCustomAppParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get custom app params
func (o *GetCustomAppParams) WithContext(ctx context.Context) *GetCustomAppParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get custom app params
func (o *GetCustomAppParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get custom app params
func (o *GetCustomAppParams) WithHTTPClient(client *http.Client) *GetCustomAppParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get custom app params
func (o *GetCustomAppParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCustomAppID adds the customAppID to the get custom app params
func (o *GetCustomAppParams) WithCustomAppID(customAppID string) *GetCustomAppParams {
	o.SetCustomAppID(customAppID)
	return o
}

// SetCustomAppID adds the customAppId to the get custom app params
func (o *GetCustomAppParams) SetCustomAppID(customAppID string) {
	o.CustomAppID = customAppID
}

// WithIfMatch adds the ifMatch to the get custom app params
func (o *GetCustomAppParams) WithIfMatch(ifMatch *string) *GetCustomAppParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get custom app params
func (o *GetCustomAppParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the get custom app params
func (o *GetCustomAppParams) WithWid(wid string) *GetCustomAppParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get custom app params
func (o *GetCustomAppParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetCustomAppParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param customAppID
	if err := r.SetPathParam("customAppID", o.CustomAppID); err != nil {
		return err
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
