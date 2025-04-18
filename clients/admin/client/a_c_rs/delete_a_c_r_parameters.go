// Code generated by go-swagger; DO NOT EDIT.

package a_c_rs

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

// NewDeleteACRParams creates a new DeleteACRParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteACRParams() *DeleteACRParams {
	return &DeleteACRParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteACRParamsWithTimeout creates a new DeleteACRParams object
// with the ability to set a timeout on a request.
func NewDeleteACRParamsWithTimeout(timeout time.Duration) *DeleteACRParams {
	return &DeleteACRParams{
		timeout: timeout,
	}
}

// NewDeleteACRParamsWithContext creates a new DeleteACRParams object
// with the ability to set a context for a request.
func NewDeleteACRParamsWithContext(ctx context.Context) *DeleteACRParams {
	return &DeleteACRParams{
		Context: ctx,
	}
}

// NewDeleteACRParamsWithHTTPClient creates a new DeleteACRParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteACRParamsWithHTTPClient(client *http.Client) *DeleteACRParams {
	return &DeleteACRParams{
		HTTPClient: client,
	}
}

/*
DeleteACRParams contains all the parameters to send to the API endpoint

	for the delete a c r operation.

	Typically these are written to a http.Request.
*/
type DeleteACRParams struct {

	/* AcrID.

	   ACR ID
	*/
	AcrID string

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

// WithDefaults hydrates default values in the delete a c r params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteACRParams) WithDefaults() *DeleteACRParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete a c r params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteACRParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := DeleteACRParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the delete a c r params
func (o *DeleteACRParams) WithTimeout(timeout time.Duration) *DeleteACRParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete a c r params
func (o *DeleteACRParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete a c r params
func (o *DeleteACRParams) WithContext(ctx context.Context) *DeleteACRParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete a c r params
func (o *DeleteACRParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete a c r params
func (o *DeleteACRParams) WithHTTPClient(client *http.Client) *DeleteACRParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete a c r params
func (o *DeleteACRParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAcrID adds the acrID to the delete a c r params
func (o *DeleteACRParams) WithAcrID(acrID string) *DeleteACRParams {
	o.SetAcrID(acrID)
	return o
}

// SetAcrID adds the acrId to the delete a c r params
func (o *DeleteACRParams) SetAcrID(acrID string) {
	o.AcrID = acrID
}

// WithIfMatch adds the ifMatch to the delete a c r params
func (o *DeleteACRParams) WithIfMatch(ifMatch *string) *DeleteACRParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the delete a c r params
func (o *DeleteACRParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the delete a c r params
func (o *DeleteACRParams) WithWid(wid string) *DeleteACRParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the delete a c r params
func (o *DeleteACRParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteACRParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param acrID
	if err := r.SetPathParam("acrID", o.AcrID); err != nil {
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
