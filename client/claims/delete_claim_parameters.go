// Code generated by go-swagger; DO NOT EDIT.

package claims

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

// NewDeleteClaimParams creates a new DeleteClaimParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteClaimParams() *DeleteClaimParams {
	return &DeleteClaimParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteClaimParamsWithTimeout creates a new DeleteClaimParams object
// with the ability to set a timeout on a request.
func NewDeleteClaimParamsWithTimeout(timeout time.Duration) *DeleteClaimParams {
	return &DeleteClaimParams{
		timeout: timeout,
	}
}

// NewDeleteClaimParamsWithContext creates a new DeleteClaimParams object
// with the ability to set a context for a request.
func NewDeleteClaimParamsWithContext(ctx context.Context) *DeleteClaimParams {
	return &DeleteClaimParams{
		Context: ctx,
	}
}

// NewDeleteClaimParamsWithHTTPClient creates a new DeleteClaimParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteClaimParamsWithHTTPClient(client *http.Client) *DeleteClaimParams {
	return &DeleteClaimParams{
		HTTPClient: client,
	}
}

/* DeleteClaimParams contains all the parameters to send to the API endpoint
   for the delete claim operation.

   Typically these are written to a http.Request.
*/
type DeleteClaimParams struct {

	// Claim.
	Claim string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete claim params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteClaimParams) WithDefaults() *DeleteClaimParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete claim params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteClaimParams) SetDefaults() {
	var (
		tidDefault = string("default")
	)

	val := DeleteClaimParams{
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the delete claim params
func (o *DeleteClaimParams) WithTimeout(timeout time.Duration) *DeleteClaimParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete claim params
func (o *DeleteClaimParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete claim params
func (o *DeleteClaimParams) WithContext(ctx context.Context) *DeleteClaimParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete claim params
func (o *DeleteClaimParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete claim params
func (o *DeleteClaimParams) WithHTTPClient(client *http.Client) *DeleteClaimParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete claim params
func (o *DeleteClaimParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClaim adds the claim to the delete claim params
func (o *DeleteClaimParams) WithClaim(claim string) *DeleteClaimParams {
	o.SetClaim(claim)
	return o
}

// SetClaim adds the claim to the delete claim params
func (o *DeleteClaimParams) SetClaim(claim string) {
	o.Claim = claim
}

// WithTid adds the tid to the delete claim params
func (o *DeleteClaimParams) WithTid(tid string) *DeleteClaimParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the delete claim params
func (o *DeleteClaimParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteClaimParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param claim
	if err := r.SetPathParam("claim", o.Claim); err != nil {
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