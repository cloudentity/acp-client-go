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

// NewListServerCustomAppsParams creates a new ListServerCustomAppsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListServerCustomAppsParams() *ListServerCustomAppsParams {
	return &ListServerCustomAppsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListServerCustomAppsParamsWithTimeout creates a new ListServerCustomAppsParams object
// with the ability to set a timeout on a request.
func NewListServerCustomAppsParamsWithTimeout(timeout time.Duration) *ListServerCustomAppsParams {
	return &ListServerCustomAppsParams{
		timeout: timeout,
	}
}

// NewListServerCustomAppsParamsWithContext creates a new ListServerCustomAppsParams object
// with the ability to set a context for a request.
func NewListServerCustomAppsParamsWithContext(ctx context.Context) *ListServerCustomAppsParams {
	return &ListServerCustomAppsParams{
		Context: ctx,
	}
}

// NewListServerCustomAppsParamsWithHTTPClient creates a new ListServerCustomAppsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListServerCustomAppsParamsWithHTTPClient(client *http.Client) *ListServerCustomAppsParams {
	return &ListServerCustomAppsParams{
		HTTPClient: client,
	}
}

/*
ListServerCustomAppsParams contains all the parameters to send to the API endpoint

	for the list server custom apps operation.

	Typically these are written to a http.Request.
*/
type ListServerCustomAppsParams struct {

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

// WithDefaults hydrates default values in the list server custom apps params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListServerCustomAppsParams) WithDefaults() *ListServerCustomAppsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list server custom apps params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListServerCustomAppsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list server custom apps params
func (o *ListServerCustomAppsParams) WithTimeout(timeout time.Duration) *ListServerCustomAppsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list server custom apps params
func (o *ListServerCustomAppsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list server custom apps params
func (o *ListServerCustomAppsParams) WithContext(ctx context.Context) *ListServerCustomAppsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list server custom apps params
func (o *ListServerCustomAppsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list server custom apps params
func (o *ListServerCustomAppsParams) WithHTTPClient(client *http.Client) *ListServerCustomAppsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list server custom apps params
func (o *ListServerCustomAppsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the list server custom apps params
func (o *ListServerCustomAppsParams) WithIfMatch(ifMatch *string) *ListServerCustomAppsParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the list server custom apps params
func (o *ListServerCustomAppsParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the list server custom apps params
func (o *ListServerCustomAppsParams) WithWid(wid string) *ListServerCustomAppsParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list server custom apps params
func (o *ListServerCustomAppsParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListServerCustomAppsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
