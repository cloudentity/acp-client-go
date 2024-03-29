// Code generated by go-swagger; DO NOT EDIT.

package schemas

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

// NewDeleteSchemaParams creates a new DeleteSchemaParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteSchemaParams() *DeleteSchemaParams {
	return &DeleteSchemaParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteSchemaParamsWithTimeout creates a new DeleteSchemaParams object
// with the ability to set a timeout on a request.
func NewDeleteSchemaParamsWithTimeout(timeout time.Duration) *DeleteSchemaParams {
	return &DeleteSchemaParams{
		timeout: timeout,
	}
}

// NewDeleteSchemaParamsWithContext creates a new DeleteSchemaParams object
// with the ability to set a context for a request.
func NewDeleteSchemaParamsWithContext(ctx context.Context) *DeleteSchemaParams {
	return &DeleteSchemaParams{
		Context: ctx,
	}
}

// NewDeleteSchemaParamsWithHTTPClient creates a new DeleteSchemaParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteSchemaParamsWithHTTPClient(client *http.Client) *DeleteSchemaParams {
	return &DeleteSchemaParams{
		HTTPClient: client,
	}
}

/*
DeleteSchemaParams contains all the parameters to send to the API endpoint

	for the delete schema operation.

	Typically these are written to a http.Request.
*/
type DeleteSchemaParams struct {

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	// SchID.
	SchID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete schema params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteSchemaParams) WithDefaults() *DeleteSchemaParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete schema params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteSchemaParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete schema params
func (o *DeleteSchemaParams) WithTimeout(timeout time.Duration) *DeleteSchemaParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete schema params
func (o *DeleteSchemaParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete schema params
func (o *DeleteSchemaParams) WithContext(ctx context.Context) *DeleteSchemaParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete schema params
func (o *DeleteSchemaParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete schema params
func (o *DeleteSchemaParams) WithHTTPClient(client *http.Client) *DeleteSchemaParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete schema params
func (o *DeleteSchemaParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithIfMatch adds the ifMatch to the delete schema params
func (o *DeleteSchemaParams) WithIfMatch(ifMatch *string) *DeleteSchemaParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the delete schema params
func (o *DeleteSchemaParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithSchID adds the schID to the delete schema params
func (o *DeleteSchemaParams) WithSchID(schID string) *DeleteSchemaParams {
	o.SetSchID(schID)
	return o
}

// SetSchID adds the schId to the delete schema params
func (o *DeleteSchemaParams) SetSchID(schID string) {
	o.SchID = schID
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteSchemaParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param schID
	if err := r.SetPathParam("schID", o.SchID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
