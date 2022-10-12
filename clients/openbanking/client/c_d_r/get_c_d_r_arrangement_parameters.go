// Code generated by go-swagger; DO NOT EDIT.

package c_d_r

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

// NewGetCDRArrangementParams creates a new GetCDRArrangementParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetCDRArrangementParams() *GetCDRArrangementParams {
	return &GetCDRArrangementParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetCDRArrangementParamsWithTimeout creates a new GetCDRArrangementParams object
// with the ability to set a timeout on a request.
func NewGetCDRArrangementParamsWithTimeout(timeout time.Duration) *GetCDRArrangementParams {
	return &GetCDRArrangementParams{
		timeout: timeout,
	}
}

// NewGetCDRArrangementParamsWithContext creates a new GetCDRArrangementParams object
// with the ability to set a context for a request.
func NewGetCDRArrangementParamsWithContext(ctx context.Context) *GetCDRArrangementParams {
	return &GetCDRArrangementParams{
		Context: ctx,
	}
}

// NewGetCDRArrangementParamsWithHTTPClient creates a new GetCDRArrangementParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetCDRArrangementParamsWithHTTPClient(client *http.Client) *GetCDRArrangementParams {
	return &GetCDRArrangementParams{
		HTTPClient: client,
	}
}

/*
GetCDRArrangementParams contains all the parameters to send to the API endpoint

	for the get c d r arrangement operation.

	Typically these are written to a http.Request.
*/
type GetCDRArrangementParams struct {

	/* ArrangementID.

	   Arrangement id
	*/
	ArrangementID string

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get c d r arrangement params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCDRArrangementParams) WithDefaults() *GetCDRArrangementParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get c d r arrangement params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetCDRArrangementParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := GetCDRArrangementParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get c d r arrangement params
func (o *GetCDRArrangementParams) WithTimeout(timeout time.Duration) *GetCDRArrangementParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get c d r arrangement params
func (o *GetCDRArrangementParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get c d r arrangement params
func (o *GetCDRArrangementParams) WithContext(ctx context.Context) *GetCDRArrangementParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get c d r arrangement params
func (o *GetCDRArrangementParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get c d r arrangement params
func (o *GetCDRArrangementParams) WithHTTPClient(client *http.Client) *GetCDRArrangementParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get c d r arrangement params
func (o *GetCDRArrangementParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithArrangementID adds the arrangementID to the get c d r arrangement params
func (o *GetCDRArrangementParams) WithArrangementID(arrangementID string) *GetCDRArrangementParams {
	o.SetArrangementID(arrangementID)
	return o
}

// SetArrangementID adds the arrangementId to the get c d r arrangement params
func (o *GetCDRArrangementParams) SetArrangementID(arrangementID string) {
	o.ArrangementID = arrangementID
}

// WithWid adds the wid to the get c d r arrangement params
func (o *GetCDRArrangementParams) WithWid(wid string) *GetCDRArrangementParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the get c d r arrangement params
func (o *GetCDRArrangementParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *GetCDRArrangementParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param arrangementID
	if err := r.SetPathParam("arrangementID", o.ArrangementID); err != nil {
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
