// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewListClientsSystemParams creates a new ListClientsSystemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListClientsSystemParams() *ListClientsSystemParams {
	return &ListClientsSystemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListClientsSystemParamsWithTimeout creates a new ListClientsSystemParams object
// with the ability to set a timeout on a request.
func NewListClientsSystemParamsWithTimeout(timeout time.Duration) *ListClientsSystemParams {
	return &ListClientsSystemParams{
		timeout: timeout,
	}
}

// NewListClientsSystemParamsWithContext creates a new ListClientsSystemParams object
// with the ability to set a context for a request.
func NewListClientsSystemParamsWithContext(ctx context.Context) *ListClientsSystemParams {
	return &ListClientsSystemParams{
		Context: ctx,
	}
}

// NewListClientsSystemParamsWithHTTPClient creates a new ListClientsSystemParams object
// with the ability to set a custom HTTPClient for a request.
func NewListClientsSystemParamsWithHTTPClient(client *http.Client) *ListClientsSystemParams {
	return &ListClientsSystemParams{
		HTTPClient: client,
	}
}

/*
ListClientsSystemParams contains all the parameters to send to the API endpoint

	for the list clients system operation.

	Typically these are written to a http.Request.
*/
type ListClientsSystemParams struct {

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list clients system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsSystemParams) WithDefaults() *ListClientsSystemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list clients system params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsSystemParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := ListClientsSystemParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list clients system params
func (o *ListClientsSystemParams) WithTimeout(timeout time.Duration) *ListClientsSystemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list clients system params
func (o *ListClientsSystemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list clients system params
func (o *ListClientsSystemParams) WithContext(ctx context.Context) *ListClientsSystemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list clients system params
func (o *ListClientsSystemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list clients system params
func (o *ListClientsSystemParams) WithHTTPClient(client *http.Client) *ListClientsSystemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list clients system params
func (o *ListClientsSystemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithWid adds the wid to the list clients system params
func (o *ListClientsSystemParams) WithWid(wid string) *ListClientsSystemParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list clients system params
func (o *ListClientsSystemParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListClientsSystemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
