// Code generated by go-swagger; DO NOT EDIT.

package scopes

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

	"github.com/cloudentity/acp-client-go/models"
)

// NewUpdateScopeParams creates a new UpdateScopeParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateScopeParams() *UpdateScopeParams {
	return &UpdateScopeParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateScopeParamsWithTimeout creates a new UpdateScopeParams object
// with the ability to set a timeout on a request.
func NewUpdateScopeParamsWithTimeout(timeout time.Duration) *UpdateScopeParams {
	return &UpdateScopeParams{
		timeout: timeout,
	}
}

// NewUpdateScopeParamsWithContext creates a new UpdateScopeParams object
// with the ability to set a context for a request.
func NewUpdateScopeParamsWithContext(ctx context.Context) *UpdateScopeParams {
	return &UpdateScopeParams{
		Context: ctx,
	}
}

// NewUpdateScopeParamsWithHTTPClient creates a new UpdateScopeParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateScopeParamsWithHTTPClient(client *http.Client) *UpdateScopeParams {
	return &UpdateScopeParams{
		HTTPClient: client,
	}
}

/* UpdateScopeParams contains all the parameters to send to the API endpoint
   for the update scope operation.

   Typically these are written to a http.Request.
*/
type UpdateScopeParams struct {

	// Scope.
	Scope *models.Scope

	// Scp.
	ScopeID string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update scope params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateScopeParams) WithDefaults() *UpdateScopeParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update scope params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateScopeParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := UpdateScopeParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update scope params
func (o *UpdateScopeParams) WithTimeout(timeout time.Duration) *UpdateScopeParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update scope params
func (o *UpdateScopeParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update scope params
func (o *UpdateScopeParams) WithContext(ctx context.Context) *UpdateScopeParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update scope params
func (o *UpdateScopeParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update scope params
func (o *UpdateScopeParams) WithHTTPClient(client *http.Client) *UpdateScopeParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update scope params
func (o *UpdateScopeParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithScope adds the scope to the update scope params
func (o *UpdateScopeParams) WithScope(scope *models.Scope) *UpdateScopeParams {
	o.SetScope(scope)
	return o
}

// SetScope adds the scope to the update scope params
func (o *UpdateScopeParams) SetScope(scope *models.Scope) {
	o.Scope = scope
}

// WithScopeID adds the scp to the update scope params
func (o *UpdateScopeParams) WithScopeID(scp string) *UpdateScopeParams {
	o.SetScopeID(scp)
	return o
}

// SetScopeID adds the scp to the update scope params
func (o *UpdateScopeParams) SetScopeID(scp string) {
	o.ScopeID = scp
}

// WithTid adds the tid to the update scope params
func (o *UpdateScopeParams) WithTid(tid string) *UpdateScopeParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the update scope params
func (o *UpdateScopeParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateScopeParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Scope != nil {
		if err := r.SetBodyParam(o.Scope); err != nil {
			return err
		}
	}

	// path param scp
	if err := r.SetPathParam("scp", o.ScopeID); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
