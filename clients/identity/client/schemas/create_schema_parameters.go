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

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// NewCreateSchemaParams creates a new CreateSchemaParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateSchemaParams() *CreateSchemaParams {
	return &CreateSchemaParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateSchemaParamsWithTimeout creates a new CreateSchemaParams object
// with the ability to set a timeout on a request.
func NewCreateSchemaParamsWithTimeout(timeout time.Duration) *CreateSchemaParams {
	return &CreateSchemaParams{
		timeout: timeout,
	}
}

// NewCreateSchemaParamsWithContext creates a new CreateSchemaParams object
// with the ability to set a context for a request.
func NewCreateSchemaParamsWithContext(ctx context.Context) *CreateSchemaParams {
	return &CreateSchemaParams{
		Context: ctx,
	}
}

// NewCreateSchemaParamsWithHTTPClient creates a new CreateSchemaParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateSchemaParamsWithHTTPClient(client *http.Client) *CreateSchemaParams {
	return &CreateSchemaParams{
		HTTPClient: client,
	}
}

/*
CreateSchemaParams contains all the parameters to send to the API endpoint

	for the create schema operation.

	Typically these are written to a http.Request.
*/
type CreateSchemaParams struct {

	// Schema.
	Schema *models.Schema

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create schema params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSchemaParams) WithDefaults() *CreateSchemaParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create schema params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSchemaParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create schema params
func (o *CreateSchemaParams) WithTimeout(timeout time.Duration) *CreateSchemaParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create schema params
func (o *CreateSchemaParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create schema params
func (o *CreateSchemaParams) WithContext(ctx context.Context) *CreateSchemaParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create schema params
func (o *CreateSchemaParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create schema params
func (o *CreateSchemaParams) WithHTTPClient(client *http.Client) *CreateSchemaParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create schema params
func (o *CreateSchemaParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSchema adds the schema to the create schema params
func (o *CreateSchemaParams) WithSchema(schema *models.Schema) *CreateSchemaParams {
	o.SetSchema(schema)
	return o
}

// SetSchema adds the schema to the create schema params
func (o *CreateSchemaParams) SetSchema(schema *models.Schema) {
	o.Schema = schema
}

// WriteToRequest writes these params to a swagger request
func (o *CreateSchemaParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Schema != nil {
		if err := r.SetBodyParam(o.Schema); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
