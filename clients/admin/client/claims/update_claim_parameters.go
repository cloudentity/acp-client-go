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

	"github.com/cloudentity/acp-client-go/clients/admin/models"
)

// NewUpdateClaimParams creates a new UpdateClaimParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateClaimParams() *UpdateClaimParams {
	return &UpdateClaimParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateClaimParamsWithTimeout creates a new UpdateClaimParams object
// with the ability to set a timeout on a request.
func NewUpdateClaimParamsWithTimeout(timeout time.Duration) *UpdateClaimParams {
	return &UpdateClaimParams{
		timeout: timeout,
	}
}

// NewUpdateClaimParamsWithContext creates a new UpdateClaimParams object
// with the ability to set a context for a request.
func NewUpdateClaimParamsWithContext(ctx context.Context) *UpdateClaimParams {
	return &UpdateClaimParams{
		Context: ctx,
	}
}

// NewUpdateClaimParamsWithHTTPClient creates a new UpdateClaimParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateClaimParamsWithHTTPClient(client *http.Client) *UpdateClaimParams {
	return &UpdateClaimParams{
		HTTPClient: client,
	}
}

/*
UpdateClaimParams contains all the parameters to send to the API endpoint

	for the update claim operation.

	Typically these are written to a http.Request.
*/
type UpdateClaimParams struct {

	// UpdateClaimBody.
	UpdateClaimBody *models.Claim

	// Claim.
	Claim string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update claim params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateClaimParams) WithDefaults() *UpdateClaimParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update claim params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateClaimParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update claim params
func (o *UpdateClaimParams) WithTimeout(timeout time.Duration) *UpdateClaimParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update claim params
func (o *UpdateClaimParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update claim params
func (o *UpdateClaimParams) WithContext(ctx context.Context) *UpdateClaimParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update claim params
func (o *UpdateClaimParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update claim params
func (o *UpdateClaimParams) WithHTTPClient(client *http.Client) *UpdateClaimParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update claim params
func (o *UpdateClaimParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithUpdateClaimBody adds the updateClaimBody to the update claim params
func (o *UpdateClaimParams) WithUpdateClaimBody(updateClaimBody *models.Claim) *UpdateClaimParams {
	o.SetUpdateClaimBody(updateClaimBody)
	return o
}

// SetUpdateClaimBody adds the updateClaimBody to the update claim params
func (o *UpdateClaimParams) SetUpdateClaimBody(updateClaimBody *models.Claim) {
	o.UpdateClaimBody = updateClaimBody
}

// WithClaim adds the claim to the update claim params
func (o *UpdateClaimParams) WithClaim(claim string) *UpdateClaimParams {
	o.SetClaim(claim)
	return o
}

// SetClaim adds the claim to the update claim params
func (o *UpdateClaimParams) SetClaim(claim string) {
	o.Claim = claim
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateClaimParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.UpdateClaimBody != nil {
		if err := r.SetBodyParam(o.UpdateClaimBody); err != nil {
			return err
		}
	}

	// path param claim
	if err := r.SetPathParam("claim", o.Claim); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
