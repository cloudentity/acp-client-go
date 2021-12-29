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

// NewCreateAzureIDPParams creates a new CreateAzureIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateAzureIDPParams() *CreateAzureIDPParams {
	return &CreateAzureIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateAzureIDPParamsWithTimeout creates a new CreateAzureIDPParams object
// with the ability to set a timeout on a request.
func NewCreateAzureIDPParamsWithTimeout(timeout time.Duration) *CreateAzureIDPParams {
	return &CreateAzureIDPParams{
		timeout: timeout,
	}
}

// NewCreateAzureIDPParamsWithContext creates a new CreateAzureIDPParams object
// with the ability to set a context for a request.
func NewCreateAzureIDPParamsWithContext(ctx context.Context) *CreateAzureIDPParams {
	return &CreateAzureIDPParams{
		Context: ctx,
	}
}

// NewCreateAzureIDPParamsWithHTTPClient creates a new CreateAzureIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateAzureIDPParamsWithHTTPClient(client *http.Client) *CreateAzureIDPParams {
	return &CreateAzureIDPParams{
		HTTPClient: client,
	}
}

/* CreateAzureIDPParams contains all the parameters to send to the API endpoint
   for the create azure ID p operation.

   Typically these are written to a http.Request.
*/
type CreateAzureIDPParams struct {

	/* AzureIDP.

	   AzureIDP
	*/
	AzureIDP *models.AzureIDP

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create azure ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateAzureIDPParams) WithDefaults() *CreateAzureIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create azure ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateAzureIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateAzureIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create azure ID p params
func (o *CreateAzureIDPParams) WithTimeout(timeout time.Duration) *CreateAzureIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create azure ID p params
func (o *CreateAzureIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create azure ID p params
func (o *CreateAzureIDPParams) WithContext(ctx context.Context) *CreateAzureIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create azure ID p params
func (o *CreateAzureIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create azure ID p params
func (o *CreateAzureIDPParams) WithHTTPClient(client *http.Client) *CreateAzureIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create azure ID p params
func (o *CreateAzureIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAzureIDP adds the azureIDP to the create azure ID p params
func (o *CreateAzureIDPParams) WithAzureIDP(azureIDP *models.AzureIDP) *CreateAzureIDPParams {
	o.SetAzureIDP(azureIDP)
	return o
}

// SetAzureIDP adds the azureIdP to the create azure ID p params
func (o *CreateAzureIDPParams) SetAzureIDP(azureIDP *models.AzureIDP) {
	o.AzureIDP = azureIDP
}

// WithWid adds the wid to the create azure ID p params
func (o *CreateAzureIDPParams) WithWid(wid string) *CreateAzureIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create azure ID p params
func (o *CreateAzureIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateAzureIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.AzureIDP != nil {
		if err := r.SetBodyParam(o.AzureIDP); err != nil {
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
