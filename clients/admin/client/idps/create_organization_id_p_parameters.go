// Code generated by go-swagger; DO NOT EDIT.

package idps

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

// NewCreateOrganizationIDPParams creates a new CreateOrganizationIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateOrganizationIDPParams() *CreateOrganizationIDPParams {
	return &CreateOrganizationIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateOrganizationIDPParamsWithTimeout creates a new CreateOrganizationIDPParams object
// with the ability to set a timeout on a request.
func NewCreateOrganizationIDPParamsWithTimeout(timeout time.Duration) *CreateOrganizationIDPParams {
	return &CreateOrganizationIDPParams{
		timeout: timeout,
	}
}

// NewCreateOrganizationIDPParamsWithContext creates a new CreateOrganizationIDPParams object
// with the ability to set a context for a request.
func NewCreateOrganizationIDPParamsWithContext(ctx context.Context) *CreateOrganizationIDPParams {
	return &CreateOrganizationIDPParams{
		Context: ctx,
	}
}

// NewCreateOrganizationIDPParamsWithHTTPClient creates a new CreateOrganizationIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateOrganizationIDPParamsWithHTTPClient(client *http.Client) *CreateOrganizationIDPParams {
	return &CreateOrganizationIDPParams{
		HTTPClient: client,
	}
}

/*
CreateOrganizationIDPParams contains all the parameters to send to the API endpoint

	for the create organization ID p operation.

	Typically these are written to a http.Request.
*/
type CreateOrganizationIDPParams struct {

	/* OrganizationIDP.

	   OrganizationIDP
	*/
	OrganizationIDP *models.OrganizationIDP

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create organization ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateOrganizationIDPParams) WithDefaults() *CreateOrganizationIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create organization ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateOrganizationIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateOrganizationIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create organization ID p params
func (o *CreateOrganizationIDPParams) WithTimeout(timeout time.Duration) *CreateOrganizationIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create organization ID p params
func (o *CreateOrganizationIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create organization ID p params
func (o *CreateOrganizationIDPParams) WithContext(ctx context.Context) *CreateOrganizationIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create organization ID p params
func (o *CreateOrganizationIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create organization ID p params
func (o *CreateOrganizationIDPParams) WithHTTPClient(client *http.Client) *CreateOrganizationIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create organization ID p params
func (o *CreateOrganizationIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithOrganizationIDP adds the organizationIDP to the create organization ID p params
func (o *CreateOrganizationIDPParams) WithOrganizationIDP(organizationIDP *models.OrganizationIDP) *CreateOrganizationIDPParams {
	o.SetOrganizationIDP(organizationIDP)
	return o
}

// SetOrganizationIDP adds the organizationIdP to the create organization ID p params
func (o *CreateOrganizationIDPParams) SetOrganizationIDP(organizationIDP *models.OrganizationIDP) {
	o.OrganizationIDP = organizationIDP
}

// WithIfMatch adds the ifMatch to the create organization ID p params
func (o *CreateOrganizationIDPParams) WithIfMatch(ifMatch *string) *CreateOrganizationIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create organization ID p params
func (o *CreateOrganizationIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the create organization ID p params
func (o *CreateOrganizationIDPParams) WithWid(wid string) *CreateOrganizationIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create organization ID p params
func (o *CreateOrganizationIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateOrganizationIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.OrganizationIDP != nil {
		if err := r.SetBodyParam(o.OrganizationIDP); err != nil {
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
