// Code generated by go-swagger; DO NOT EDIT.

package m_a_n_a_g_e_m_e_n_t

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

// NewListCustomerClientsParams creates a new ListCustomerClientsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListCustomerClientsParams() *ListCustomerClientsParams {
	return &ListCustomerClientsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListCustomerClientsParamsWithTimeout creates a new ListCustomerClientsParams object
// with the ability to set a timeout on a request.
func NewListCustomerClientsParamsWithTimeout(timeout time.Duration) *ListCustomerClientsParams {
	return &ListCustomerClientsParams{
		timeout: timeout,
	}
}

// NewListCustomerClientsParamsWithContext creates a new ListCustomerClientsParams object
// with the ability to set a context for a request.
func NewListCustomerClientsParamsWithContext(ctx context.Context) *ListCustomerClientsParams {
	return &ListCustomerClientsParams{
		Context: ctx,
	}
}

// NewListCustomerClientsParamsWithHTTPClient creates a new ListCustomerClientsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListCustomerClientsParamsWithHTTPClient(client *http.Client) *ListCustomerClientsParams {
	return &ListCustomerClientsParams{
		HTTPClient: client,
	}
}

/*
ListCustomerClientsParams contains all the parameters to send to the API endpoint

	for the list customer clients operation.

	Typically these are written to a http.Request.
*/
type ListCustomerClientsParams struct {

	/* Wid.

	   Workspace id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list customer clients params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListCustomerClientsParams) WithDefaults() *ListCustomerClientsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list customer clients params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListCustomerClientsParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := ListCustomerClientsParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list customer clients params
func (o *ListCustomerClientsParams) WithTimeout(timeout time.Duration) *ListCustomerClientsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list customer clients params
func (o *ListCustomerClientsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list customer clients params
func (o *ListCustomerClientsParams) WithContext(ctx context.Context) *ListCustomerClientsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list customer clients params
func (o *ListCustomerClientsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list customer clients params
func (o *ListCustomerClientsParams) WithHTTPClient(client *http.Client) *ListCustomerClientsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list customer clients params
func (o *ListCustomerClientsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithWid adds the wid to the list customer clients params
func (o *ListCustomerClientsParams) WithWid(wid string) *ListCustomerClientsParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the list customer clients params
func (o *ListCustomerClientsParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *ListCustomerClientsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
