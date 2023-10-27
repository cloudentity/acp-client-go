// Code generated by go-swagger; DO NOT EDIT.

package services

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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// NewCreateServiceParams creates a new CreateServiceParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateServiceParams() *CreateServiceParams {
	return &CreateServiceParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateServiceParamsWithTimeout creates a new CreateServiceParams object
// with the ability to set a timeout on a request.
func NewCreateServiceParamsWithTimeout(timeout time.Duration) *CreateServiceParams {
	return &CreateServiceParams{
		timeout: timeout,
	}
}

// NewCreateServiceParamsWithContext creates a new CreateServiceParams object
// with the ability to set a context for a request.
func NewCreateServiceParamsWithContext(ctx context.Context) *CreateServiceParams {
	return &CreateServiceParams{
		Context: ctx,
	}
}

// NewCreateServiceParamsWithHTTPClient creates a new CreateServiceParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateServiceParamsWithHTTPClient(client *http.Client) *CreateServiceParams {
	return &CreateServiceParams{
		HTTPClient: client,
	}
}

/*
CreateServiceParams contains all the parameters to send to the API endpoint

	for the create service operation.

	Typically these are written to a http.Request.
*/
type CreateServiceParams struct {

	// Service.
	Service *models.Service

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateServiceParams) WithDefaults() *CreateServiceParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create service params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateServiceParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create service params
func (o *CreateServiceParams) WithTimeout(timeout time.Duration) *CreateServiceParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create service params
func (o *CreateServiceParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create service params
func (o *CreateServiceParams) WithContext(ctx context.Context) *CreateServiceParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create service params
func (o *CreateServiceParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create service params
func (o *CreateServiceParams) WithHTTPClient(client *http.Client) *CreateServiceParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create service params
func (o *CreateServiceParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithService adds the service to the create service params
func (o *CreateServiceParams) WithService(service *models.Service) *CreateServiceParams {
	o.SetService(service)
	return o
}

// SetService adds the service to the create service params
func (o *CreateServiceParams) SetService(service *models.Service) {
	o.Service = service
}

// WithIfMatch adds the ifMatch to the create service params
func (o *CreateServiceParams) WithIfMatch(ifMatch *string) *CreateServiceParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create service params
func (o *CreateServiceParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *CreateServiceParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Service != nil {
		if err := r.SetBodyParam(o.Service); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
