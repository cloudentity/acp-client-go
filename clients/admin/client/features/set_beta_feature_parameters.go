// Code generated by go-swagger; DO NOT EDIT.

package features

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

// NewSetBetaFeatureParams creates a new SetBetaFeatureParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSetBetaFeatureParams() *SetBetaFeatureParams {
	return &SetBetaFeatureParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSetBetaFeatureParamsWithTimeout creates a new SetBetaFeatureParams object
// with the ability to set a timeout on a request.
func NewSetBetaFeatureParamsWithTimeout(timeout time.Duration) *SetBetaFeatureParams {
	return &SetBetaFeatureParams{
		timeout: timeout,
	}
}

// NewSetBetaFeatureParamsWithContext creates a new SetBetaFeatureParams object
// with the ability to set a context for a request.
func NewSetBetaFeatureParamsWithContext(ctx context.Context) *SetBetaFeatureParams {
	return &SetBetaFeatureParams{
		Context: ctx,
	}
}

// NewSetBetaFeatureParamsWithHTTPClient creates a new SetBetaFeatureParams object
// with the ability to set a custom HTTPClient for a request.
func NewSetBetaFeatureParamsWithHTTPClient(client *http.Client) *SetBetaFeatureParams {
	return &SetBetaFeatureParams{
		HTTPClient: client,
	}
}

/*
SetBetaFeatureParams contains all the parameters to send to the API endpoint

	for the set beta feature operation.

	Typically these are written to a http.Request.
*/
type SetBetaFeatureParams struct {

	// SetTenantFeature.
	SetTenantFeature *models.SetBetaFeature

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the set beta feature params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetBetaFeatureParams) WithDefaults() *SetBetaFeatureParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the set beta feature params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SetBetaFeatureParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the set beta feature params
func (o *SetBetaFeatureParams) WithTimeout(timeout time.Duration) *SetBetaFeatureParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the set beta feature params
func (o *SetBetaFeatureParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the set beta feature params
func (o *SetBetaFeatureParams) WithContext(ctx context.Context) *SetBetaFeatureParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the set beta feature params
func (o *SetBetaFeatureParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the set beta feature params
func (o *SetBetaFeatureParams) WithHTTPClient(client *http.Client) *SetBetaFeatureParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the set beta feature params
func (o *SetBetaFeatureParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSetTenantFeature adds the setTenantFeature to the set beta feature params
func (o *SetBetaFeatureParams) WithSetTenantFeature(setTenantFeature *models.SetBetaFeature) *SetBetaFeatureParams {
	o.SetSetTenantFeature(setTenantFeature)
	return o
}

// SetSetTenantFeature adds the setTenantFeature to the set beta feature params
func (o *SetBetaFeatureParams) SetSetTenantFeature(setTenantFeature *models.SetBetaFeature) {
	o.SetTenantFeature = setTenantFeature
}

// WriteToRequest writes these params to a swagger request
func (o *SetBetaFeatureParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.SetTenantFeature != nil {
		if err := r.SetBodyParam(o.SetTenantFeature); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
