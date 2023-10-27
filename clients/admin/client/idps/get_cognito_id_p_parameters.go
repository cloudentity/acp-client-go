// Code generated by go-swagger; DO NOT EDIT.

package idps

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

// NewGetCognitoIDPParams creates a new GetCognitoIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCognitoIDPParams() *GetCognitoIDPParams {
	return &GetCognitoIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCognitoIDPParamsWithTimeout creates a new GetCognitoIDPParams object
// with the ability to set a timeout on a request.
func NewGetCognitoIDPParamsWithTimeout(timeout time.Duration) *GetCognitoIDPParams {
	return &GetCognitoIDPParams{
		timeout: timeout,
	}
}

// NewGetCognitoIDPParamsWithContext creates a new GetCognitoIDPParams object
// with the ability to set a context for a request.
func NewGetCognitoIDPParamsWithContext(ctx context.Context) *GetCognitoIDPParams {
	return &GetCognitoIDPParams{
		Context: ctx,
	}
}

// NewGetCognitoIDPParamsWithHTTPClient creates a new GetCognitoIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCognitoIDPParamsWithHTTPClient(client *http.Client) *GetCognitoIDPParams {
	return &GetCognitoIDPParams{
		HTTPClient: client,
	}
}

/*
GetCognitoIDPParams contains all the parameters to send to the API endpoint

	for the get cognito ID p operation.

	Typically these are written to a http.Request.
*/
type GetCognitoIDPParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Iid.

	   IDP id
	*/
	Iid string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get cognito ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCognitoIDPParams) WithDefaults() *GetCognitoIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get cognito ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCognitoIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetCognitoIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get cognito ID p params
func (o *GetCognitoIDPParams) WithTimeout(timeout time.Duration) *GetCognitoIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get cognito ID p params
func (o *GetCognitoIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get cognito ID p params
func (o *GetCognitoIDPParams) WithContext(ctx context.Context) *GetCognitoIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get cognito ID p params
func (o *GetCognitoIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get cognito ID p params
func (o *GetCognitoIDPParams) WithHTTPClient(client *http.Client) *GetCognitoIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get cognito ID p params
func (o *GetCognitoIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the get cognito ID p params
func (o *GetCognitoIDPParams) WithIfMatch(ifMatch *string) *GetCognitoIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the get cognito ID p params
func (o *GetCognitoIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the get cognito ID p params
func (o *GetCognitoIDPParams) WithIid(iid string) *GetCognitoIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get cognito ID p params
func (o *GetCognitoIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the get cognito ID p params
func (o *GetCognitoIDPParams) WithWid(wid string) *GetCognitoIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get cognito ID p params
func (o *GetCognitoIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetCognitoIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param iid
	if err := r.SetPathParam("iid", o.Iid); err != nil {
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
