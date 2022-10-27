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

// NewListClientsForDeveloperParams creates a new ListClientsForDeveloperParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListClientsForDeveloperParams() *ListClientsForDeveloperParams {
	return &ListClientsForDeveloperParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListClientsForDeveloperParamsWithTimeout creates a new ListClientsForDeveloperParams object
// with the ability to set a timeout on a request.
func NewListClientsForDeveloperParamsWithTimeout(timeout time.Duration) *ListClientsForDeveloperParams {
	return &ListClientsForDeveloperParams{
		timeout: timeout,
	}
}

// NewListClientsForDeveloperParamsWithContext creates a new ListClientsForDeveloperParams object
// with the ability to set a context for a request.
func NewListClientsForDeveloperParamsWithContext(ctx context.Context) *ListClientsForDeveloperParams {
	return &ListClientsForDeveloperParams{
		Context: ctx,
	}
}

// NewListClientsForDeveloperParamsWithHTTPClient creates a new ListClientsForDeveloperParams object
// with the ability to set a custom HTTPClient for a request.
func NewListClientsForDeveloperParamsWithHTTPClient(client *http.Client) *ListClientsForDeveloperParams {
	return &ListClientsForDeveloperParams{
		HTTPClient: client,
	}
}

/*
ListClientsForDeveloperParams contains all the parameters to send to the API endpoint

	for the list clients for developer operation.

	Typically these are written to a http.Request.
*/
type ListClientsForDeveloperParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list clients for developer params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsForDeveloperParams) WithDefaults() *ListClientsForDeveloperParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list clients for developer params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListClientsForDeveloperParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list clients for developer params
func (o *ListClientsForDeveloperParams) WithTimeout(timeout time.Duration) *ListClientsForDeveloperParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list clients for developer params
func (o *ListClientsForDeveloperParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list clients for developer params
func (o *ListClientsForDeveloperParams) WithContext(ctx context.Context) *ListClientsForDeveloperParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list clients for developer params
func (o *ListClientsForDeveloperParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list clients for developer params
func (o *ListClientsForDeveloperParams) WithHTTPClient(client *http.Client) *ListClientsForDeveloperParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list clients for developer params
func (o *ListClientsForDeveloperParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ListClientsForDeveloperParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
