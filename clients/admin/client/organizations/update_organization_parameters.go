// Code generated by go-swagger; DO NOT EDIT.

package organizations

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

// NewUpdateOrganizationParams creates a new UpdateOrganizationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateOrganizationParams() *UpdateOrganizationParams {
	return &UpdateOrganizationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateOrganizationParamsWithTimeout creates a new UpdateOrganizationParams object
// with the ability to set a timeout on a request.
func NewUpdateOrganizationParamsWithTimeout(timeout time.Duration) *UpdateOrganizationParams {
	return &UpdateOrganizationParams{
		timeout: timeout,
	}
}

// NewUpdateOrganizationParamsWithContext creates a new UpdateOrganizationParams object
// with the ability to set a context for a request.
func NewUpdateOrganizationParamsWithContext(ctx context.Context) *UpdateOrganizationParams {
	return &UpdateOrganizationParams{
		Context: ctx,
	}
}

// NewUpdateOrganizationParamsWithHTTPClient creates a new UpdateOrganizationParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateOrganizationParamsWithHTTPClient(client *http.Client) *UpdateOrganizationParams {
	return &UpdateOrganizationParams{
		HTTPClient: client,
	}
}

/*
UpdateOrganizationParams contains all the parameters to send to the API endpoint

	for the update organization operation.

	Typically these are written to a http.Request.
*/
type UpdateOrganizationParams struct {

	// Org.
	Org *models.Org

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Organization id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update organization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateOrganizationParams) WithDefaults() *UpdateOrganizationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update organization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateOrganizationParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := UpdateOrganizationParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update organization params
func (o *UpdateOrganizationParams) WithTimeout(timeout time.Duration) *UpdateOrganizationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update organization params
func (o *UpdateOrganizationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update organization params
func (o *UpdateOrganizationParams) WithContext(ctx context.Context) *UpdateOrganizationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update organization params
func (o *UpdateOrganizationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update organization params
func (o *UpdateOrganizationParams) WithHTTPClient(client *http.Client) *UpdateOrganizationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update organization params
func (o *UpdateOrganizationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithOrg adds the org to the update organization params
func (o *UpdateOrganizationParams) WithOrg(org *models.Org) *UpdateOrganizationParams {
	o.SetOrg(org)
	return o
}

// SetOrg adds the org to the update organization params
func (o *UpdateOrganizationParams) SetOrg(org *models.Org) {
	o.Org = org
}

// WithIfMatch adds the ifMatch to the update organization params
func (o *UpdateOrganizationParams) WithIfMatch(ifMatch *string) *UpdateOrganizationParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update organization params
func (o *UpdateOrganizationParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the update organization params
func (o *UpdateOrganizationParams) WithWid(wid string) *UpdateOrganizationParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the update organization params
func (o *UpdateOrganizationParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateOrganizationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Org != nil {
		if err := r.SetBodyParam(o.Org); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param wid
	if err := r.SetPathParam("wid", o.Wid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
