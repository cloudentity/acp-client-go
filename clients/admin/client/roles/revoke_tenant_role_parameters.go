// Code generated by go-swagger; DO NOT EDIT.

package roles

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

// NewRevokeTenantRoleParams creates a new RevokeTenantRoleParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRevokeTenantRoleParams() *RevokeTenantRoleParams {
	return &RevokeTenantRoleParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRevokeTenantRoleParamsWithTimeout creates a new RevokeTenantRoleParams object
// with the ability to set a timeout on a request.
func NewRevokeTenantRoleParamsWithTimeout(timeout time.Duration) *RevokeTenantRoleParams {
	return &RevokeTenantRoleParams{
		timeout: timeout,
	}
}

// NewRevokeTenantRoleParamsWithContext creates a new RevokeTenantRoleParams object
// with the ability to set a context for a request.
func NewRevokeTenantRoleParamsWithContext(ctx context.Context) *RevokeTenantRoleParams {
	return &RevokeTenantRoleParams{
		Context: ctx,
	}
}

// NewRevokeTenantRoleParamsWithHTTPClient creates a new RevokeTenantRoleParams object
// with the ability to set a custom HTTPClient for a request.
func NewRevokeTenantRoleParamsWithHTTPClient(client *http.Client) *RevokeTenantRoleParams {
	return &RevokeTenantRoleParams{
		HTTPClient: client,
	}
}

/*
RevokeTenantRoleParams contains all the parameters to send to the API endpoint

	for the revoke tenant role operation.

	Typically these are written to a http.Request.
*/
type RevokeTenantRoleParams struct {

	// Request.
	Request *models.RevokeTenantRoleRequest

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the revoke tenant role params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeTenantRoleParams) WithDefaults() *RevokeTenantRoleParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the revoke tenant role params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RevokeTenantRoleParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the revoke tenant role params
func (o *RevokeTenantRoleParams) WithTimeout(timeout time.Duration) *RevokeTenantRoleParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the revoke tenant role params
func (o *RevokeTenantRoleParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the revoke tenant role params
func (o *RevokeTenantRoleParams) WithContext(ctx context.Context) *RevokeTenantRoleParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the revoke tenant role params
func (o *RevokeTenantRoleParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the revoke tenant role params
func (o *RevokeTenantRoleParams) WithHTTPClient(client *http.Client) *RevokeTenantRoleParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the revoke tenant role params
func (o *RevokeTenantRoleParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the revoke tenant role params
func (o *RevokeTenantRoleParams) WithRequest(request *models.RevokeTenantRoleRequest) *RevokeTenantRoleParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the revoke tenant role params
func (o *RevokeTenantRoleParams) SetRequest(request *models.RevokeTenantRoleRequest) {
	o.Request = request
}

// WithIfMatch adds the ifMatch to the revoke tenant role params
func (o *RevokeTenantRoleParams) WithIfMatch(ifMatch *string) *RevokeTenantRoleParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the revoke tenant role params
func (o *RevokeTenantRoleParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *RevokeTenantRoleParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Request != nil {
		if err := r.SetBodyParam(o.Request); err != nil {
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
