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

// NewCreateAzureB2CIDPParams creates a new CreateAzureB2CIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateAzureB2CIDPParams() *CreateAzureB2CIDPParams {
	return &CreateAzureB2CIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateAzureB2CIDPParamsWithTimeout creates a new CreateAzureB2CIDPParams object
// with the ability to set a timeout on a request.
func NewCreateAzureB2CIDPParamsWithTimeout(timeout time.Duration) *CreateAzureB2CIDPParams {
	return &CreateAzureB2CIDPParams{
		timeout: timeout,
	}
}

// NewCreateAzureB2CIDPParamsWithContext creates a new CreateAzureB2CIDPParams object
// with the ability to set a context for a request.
func NewCreateAzureB2CIDPParamsWithContext(ctx context.Context) *CreateAzureB2CIDPParams {
	return &CreateAzureB2CIDPParams{
		Context: ctx,
	}
}

// NewCreateAzureB2CIDPParamsWithHTTPClient creates a new CreateAzureB2CIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateAzureB2CIDPParamsWithHTTPClient(client *http.Client) *CreateAzureB2CIDPParams {
	return &CreateAzureB2CIDPParams{
		HTTPClient: client,
	}
}

/*
CreateAzureB2CIDPParams contains all the parameters to send to the API endpoint

	for the create azure b2 c ID p operation.

	Typically these are written to a http.Request.
*/
type CreateAzureB2CIDPParams struct {

	/* AzureB2CIDP.

	   AzureB2CIDP
	*/
	AzureB2CIDP *models.AzureB2CIDP

	/* Wid.

	   Authorization server id

	   Default: "default"
	*/
	Wid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create azure b2 c ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateAzureB2CIDPParams) WithDefaults() *CreateAzureB2CIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create azure b2 c ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateAzureB2CIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateAzureB2CIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) WithTimeout(timeout time.Duration) *CreateAzureB2CIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) WithContext(ctx context.Context) *CreateAzureB2CIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) WithHTTPClient(client *http.Client) *CreateAzureB2CIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAzureB2CIDP adds the azureB2CIDP to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) WithAzureB2CIDP(azureB2CIDP *models.AzureB2CIDP) *CreateAzureB2CIDPParams {
	o.SetAzureB2CIDP(azureB2CIDP)
	return o
}

// SetAzureB2CIDP adds the azureB2CIdP to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) SetAzureB2CIDP(azureB2CIDP *models.AzureB2CIDP) {
	o.AzureB2CIDP = azureB2CIDP
}

// WithWid adds the wid to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) WithWid(wid string) *CreateAzureB2CIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create azure b2 c ID p params
func (o *CreateAzureB2CIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateAzureB2CIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.AzureB2CIDP != nil {
		if err := r.SetBodyParam(o.AzureB2CIDP); err != nil {
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
