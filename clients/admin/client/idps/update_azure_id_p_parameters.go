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

// NewUpdateAzureIDPParams creates a new UpdateAzureIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateAzureIDPParams() *UpdateAzureIDPParams {
	return &UpdateAzureIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateAzureIDPParamsWithTimeout creates a new UpdateAzureIDPParams object
// with the ability to set a timeout on a request.
func NewUpdateAzureIDPParamsWithTimeout(timeout time.Duration) *UpdateAzureIDPParams {
	return &UpdateAzureIDPParams{
		timeout: timeout,
	}
}

// NewUpdateAzureIDPParamsWithContext creates a new UpdateAzureIDPParams object
// with the ability to set a context for a request.
func NewUpdateAzureIDPParamsWithContext(ctx context.Context) *UpdateAzureIDPParams {
	return &UpdateAzureIDPParams{
		Context: ctx,
	}
}

// NewUpdateAzureIDPParamsWithHTTPClient creates a new UpdateAzureIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateAzureIDPParamsWithHTTPClient(client *http.Client) *UpdateAzureIDPParams {
	return &UpdateAzureIDPParams{
		HTTPClient: client,
	}
}

/*
UpdateAzureIDPParams contains all the parameters to send to the API endpoint

	for the update azure ID p operation.

	Typically these are written to a http.Request.
*/
type UpdateAzureIDPParams struct {

	/* AzureIDP.

	   AzureIDP
	*/
	AzureIDP *models.AzureIDP

	/* IfMatch.

	   A server will only return requested resources if the resource matches one of the listed ETag value

	   Format: etag
	*/
	IfMatch *string

	/* Iid.

	   IDP id

	   Default: "default"
	*/
	Iid string

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update azure ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateAzureIDPParams) WithDefaults() *UpdateAzureIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update azure ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateAzureIDPParams) SetDefaults() {
	var (
		iidDefault = string("default")

		widDefault = string("default")
	)

	val := UpdateAzureIDPParams{
		Iid: iidDefault,
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update azure ID p params
func (o *UpdateAzureIDPParams) WithTimeout(timeout time.Duration) *UpdateAzureIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update azure ID p params
func (o *UpdateAzureIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update azure ID p params
func (o *UpdateAzureIDPParams) WithContext(ctx context.Context) *UpdateAzureIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update azure ID p params
func (o *UpdateAzureIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update azure ID p params
func (o *UpdateAzureIDPParams) WithHTTPClient(client *http.Client) *UpdateAzureIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update azure ID p params
func (o *UpdateAzureIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAzureIDP adds the azureIDP to the update azure ID p params
func (o *UpdateAzureIDPParams) WithAzureIDP(azureIDP *models.AzureIDP) *UpdateAzureIDPParams {
	o.SetAzureIDP(azureIDP)
	return o
}

// SetAzureIDP adds the azureIdP to the update azure ID p params
func (o *UpdateAzureIDPParams) SetAzureIDP(azureIDP *models.AzureIDP) {
	o.AzureIDP = azureIDP
}

// WithIfMatch adds the ifMatch to the update azure ID p params
func (o *UpdateAzureIDPParams) WithIfMatch(ifMatch *string) *UpdateAzureIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update azure ID p params
func (o *UpdateAzureIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the update azure ID p params
func (o *UpdateAzureIDPParams) WithIid(iid string) *UpdateAzureIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update azure ID p params
func (o *UpdateAzureIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the update azure ID p params
func (o *UpdateAzureIDPParams) WithWid(wid string) *UpdateAzureIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the update azure ID p params
func (o *UpdateAzureIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateAzureIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.AzureIDP != nil {
		if err := r.SetBodyParam(o.AzureIDP); err != nil {
			return err
		}
	}

	if o.IfMatch != nil {

		// header param if-match
		if err := r.SetHeaderParam("if-match", *o.IfMatch); err != nil {
			return err
		}
	}

	// path param iid
	if err := r.SetPathParam("iid", o.Iid); err != nil {
		return err
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
