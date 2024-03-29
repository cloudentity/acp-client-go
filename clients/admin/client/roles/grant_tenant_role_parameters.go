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

// NewGrantTenantRoleParams creates a new GrantTenantRoleParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGrantTenantRoleParams() *GrantTenantRoleParams {
	return &GrantTenantRoleParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGrantTenantRoleParamsWithTimeout creates a new GrantTenantRoleParams object
// with the ability to set a timeout on a request.
func NewGrantTenantRoleParamsWithTimeout(timeout time.Duration) *GrantTenantRoleParams {
	return &GrantTenantRoleParams{
		timeout: timeout,
	}
}

// NewGrantTenantRoleParamsWithContext creates a new GrantTenantRoleParams object
// with the ability to set a context for a request.
func NewGrantTenantRoleParamsWithContext(ctx context.Context) *GrantTenantRoleParams {
	return &GrantTenantRoleParams{
		Context: ctx,
	}
}

// NewGrantTenantRoleParamsWithHTTPClient creates a new GrantTenantRoleParams object
// with the ability to set a custom HTTPClient for a request.
func NewGrantTenantRoleParamsWithHTTPClient(client *http.Client) *GrantTenantRoleParams {
	return &GrantTenantRoleParams{
		HTTPClient: client,
	}
}

/*
GrantTenantRoleParams contains all the parameters to send to the API endpoint

	for the grant tenant role operation.

	Typically these are written to a http.Request.
*/
type GrantTenantRoleParams struct {

	// Request.
	Request *models.GrantTenantRoleRequest

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the grant tenant role params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GrantTenantRoleParams) WithDefaults() *GrantTenantRoleParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the grant tenant role params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GrantTenantRoleParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the grant tenant role params
func (o *GrantTenantRoleParams) WithTimeout(timeout time.Duration) *GrantTenantRoleParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the grant tenant role params
func (o *GrantTenantRoleParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the grant tenant role params
func (o *GrantTenantRoleParams) WithContext(ctx context.Context) *GrantTenantRoleParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the grant tenant role params
func (o *GrantTenantRoleParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the grant tenant role params
func (o *GrantTenantRoleParams) WithHTTPClient(client *http.Client) *GrantTenantRoleParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the grant tenant role params
func (o *GrantTenantRoleParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the grant tenant role params
func (o *GrantTenantRoleParams) WithRequest(request *models.GrantTenantRoleRequest) *GrantTenantRoleParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the grant tenant role params
func (o *GrantTenantRoleParams) SetRequest(request *models.GrantTenantRoleRequest) {
	o.Request = request
}

// WithIfMatch adds the ifMatch to the grant tenant role params
func (o *GrantTenantRoleParams) WithIfMatch(ifMatch *string) *GrantTenantRoleParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the grant tenant role params
func (o *GrantTenantRoleParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WriteToRequest writes these params to a swagger request
func (o *GrantTenantRoleParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
