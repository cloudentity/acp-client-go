// Code generated by go-swagger; DO NOT EDIT.

package apis

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

// NewCreateAPIParams creates a new CreateAPIParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateAPIParams() *CreateAPIParams {
	return &CreateAPIParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateAPIParamsWithTimeout creates a new CreateAPIParams object
// with the ability to set a timeout on a request.
func NewCreateAPIParamsWithTimeout(timeout time.Duration) *CreateAPIParams {
	return &CreateAPIParams{
		timeout: timeout,
	}
}

// NewCreateAPIParamsWithContext creates a new CreateAPIParams object
// with the ability to set a context for a request.
func NewCreateAPIParamsWithContext(ctx context.Context) *CreateAPIParams {
	return &CreateAPIParams{
		Context: ctx,
	}
}

// NewCreateAPIParamsWithHTTPClient creates a new CreateAPIParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateAPIParamsWithHTTPClient(client *http.Client) *CreateAPIParams {
	return &CreateAPIParams{
		HTTPClient: client,
	}
}

/*
CreateAPIParams contains all the parameters to send to the API endpoint

	for the create API operation.

	Typically these are written to a http.Request.
*/
type CreateAPIParams struct {

	/* APIBody.

	   APIBody
	*/
	APIBody *models.API

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create API params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateAPIParams) WithDefaults() *CreateAPIParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create API params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateAPIParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create API params
func (o *CreateAPIParams) WithTimeout(timeout time.Duration) *CreateAPIParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create API params
func (o *CreateAPIParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create API params
func (o *CreateAPIParams) WithContext(ctx context.Context) *CreateAPIParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create API params
func (o *CreateAPIParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create API params
func (o *CreateAPIParams) WithHTTPClient(client *http.Client) *CreateAPIParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create API params
func (o *CreateAPIParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAPIBody adds the aPIBody to the create API params
func (o *CreateAPIParams) WithAPIBody(aPIBody *models.API) *CreateAPIParams {
	o.SetAPIBody(aPIBody)
	return o
}

// SetAPIBody adds the apiBody to the create API params
func (o *CreateAPIParams) SetAPIBody(aPIBody *models.API) {
	o.APIBody = aPIBody
}

// WithIfMatch adds the ifMatch to the create API params
func (o *CreateAPIParams) WithIfMatch(ifMatch *string) *CreateAPIParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create API params
func (o *CreateAPIParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *CreateAPIParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.APIBody != nil {
		if err := r.SetBodyParam(o.APIBody); err != nil {
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
