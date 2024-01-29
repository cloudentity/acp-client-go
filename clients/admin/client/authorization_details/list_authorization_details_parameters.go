// Code generated by go-swagger; DO NOT EDIT.

package authorization_details

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

// NewListAuthorizationDetailsParams creates a new ListAuthorizationDetailsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListAuthorizationDetailsParams() *ListAuthorizationDetailsParams {
	return &ListAuthorizationDetailsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListAuthorizationDetailsParamsWithTimeout creates a new ListAuthorizationDetailsParams object
// with the ability to set a timeout on a request.
func NewListAuthorizationDetailsParamsWithTimeout(timeout time.Duration) *ListAuthorizationDetailsParams {
	return &ListAuthorizationDetailsParams{
		timeout: timeout,
	}
}

// NewListAuthorizationDetailsParamsWithContext creates a new ListAuthorizationDetailsParams object
// with the ability to set a context for a request.
func NewListAuthorizationDetailsParamsWithContext(ctx context.Context) *ListAuthorizationDetailsParams {
	return &ListAuthorizationDetailsParams{
		Context: ctx,
	}
}

// NewListAuthorizationDetailsParamsWithHTTPClient creates a new ListAuthorizationDetailsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListAuthorizationDetailsParamsWithHTTPClient(client *http.Client) *ListAuthorizationDetailsParams {
	return &ListAuthorizationDetailsParams{
		HTTPClient: client,
	}
}

/*
ListAuthorizationDetailsParams contains all the parameters to send to the API endpoint

	for the list authorization details operation.

	Typically these are written to a http.Request.
*/
type ListAuthorizationDetailsParams struct {

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

// WithDefaults hydrates default values in the list authorization details params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAuthorizationDetailsParams) WithDefaults() *ListAuthorizationDetailsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list authorization details params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListAuthorizationDetailsParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := ListAuthorizationDetailsParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list authorization details params
func (o *ListAuthorizationDetailsParams) WithTimeout(timeout time.Duration) *ListAuthorizationDetailsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list authorization details params
func (o *ListAuthorizationDetailsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list authorization details params
func (o *ListAuthorizationDetailsParams) WithContext(ctx context.Context) *ListAuthorizationDetailsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list authorization details params
func (o *ListAuthorizationDetailsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list authorization details params
func (o *ListAuthorizationDetailsParams) WithHTTPClient(client *http.Client) *ListAuthorizationDetailsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list authorization details params
func (o *ListAuthorizationDetailsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the list authorization details params
func (o *ListAuthorizationDetailsParams) WithIfMatch(ifMatch *string) *ListAuthorizationDetailsParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the list authorization details params
func (o *ListAuthorizationDetailsParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the list authorization details params
func (o *ListAuthorizationDetailsParams) WithWid(wid string) *ListAuthorizationDetailsParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list authorization details params
func (o *ListAuthorizationDetailsParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListAuthorizationDetailsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
