// Code generated by go-swagger; DO NOT EDIT.

package tenants

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

// NewListTenantsParams creates a new ListTenantsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListTenantsParams() *ListTenantsParams {
	return &ListTenantsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListTenantsParamsWithTimeout creates a new ListTenantsParams object
// with the ability to set a timeout on a request.
func NewListTenantsParamsWithTimeout(timeout time.Duration) *ListTenantsParams {
	return &ListTenantsParams{
		timeout: timeout,
	}
}

// NewListTenantsParamsWithContext creates a new ListTenantsParams object
// with the ability to set a context for a request.
func NewListTenantsParamsWithContext(ctx context.Context) *ListTenantsParams {
	return &ListTenantsParams{
		Context: ctx,
	}
}

// NewListTenantsParamsWithHTTPClient creates a new ListTenantsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListTenantsParamsWithHTTPClient(client *http.Client) *ListTenantsParams {
	return &ListTenantsParams{
		HTTPClient: client,
	}
}

/*
ListTenantsParams contains all the parameters to send to the API endpoint

	for the list tenants operation.

	Typically these are written to a http.Request.
*/
type ListTenantsParams struct {

	/* Query.

	     optional query filter
	query is in json format like {"metadata": {"registration_identifier":"john.doe@cloudentity.com"}} - parameter must be url-encoded
	supported parameters
	`metadata` - limits tenants set to tenants with metadata matches provided metadata - for simple values it does exact match, for arrays it does `contain`
	if multiple parameters provided it does logical AND between the results so tenants must match ALL parameters
	*/
	Query *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the list tenants params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListTenantsParams) WithDefaults() *ListTenantsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list tenants params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListTenantsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the list tenants params
func (o *ListTenantsParams) WithTimeout(timeout time.Duration) *ListTenantsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list tenants params
func (o *ListTenantsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list tenants params
func (o *ListTenantsParams) WithContext(ctx context.Context) *ListTenantsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list tenants params
func (o *ListTenantsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list tenants params
func (o *ListTenantsParams) WithHTTPClient(client *http.Client) *ListTenantsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list tenants params
func (o *ListTenantsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithQuery adds the query to the list tenants params
func (o *ListTenantsParams) WithQuery(query *string) *ListTenantsParams {
	o.SetQuery(query)
	return o
}

// SetQuery adds the query to the list tenants params
func (o *ListTenantsParams) SetQuery(query *string) {
	o.Query = query
}

// WriteToRequest writes these params to a swagger request
func (o *ListTenantsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Query != nil {

		// query param query
		var qrQuery string

		if o.Query != nil {
			qrQuery = *o.Query
		}
		qQuery := qrQuery
		if qQuery != "" {

			if err := r.SetQueryParam("query", qQuery); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
