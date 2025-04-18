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

// NewCreateMetaIDPParams creates a new CreateMetaIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateMetaIDPParams() *CreateMetaIDPParams {
	return &CreateMetaIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateMetaIDPParamsWithTimeout creates a new CreateMetaIDPParams object
// with the ability to set a timeout on a request.
func NewCreateMetaIDPParamsWithTimeout(timeout time.Duration) *CreateMetaIDPParams {
	return &CreateMetaIDPParams{
		timeout: timeout,
	}
}

// NewCreateMetaIDPParamsWithContext creates a new CreateMetaIDPParams object
// with the ability to set a context for a request.
func NewCreateMetaIDPParamsWithContext(ctx context.Context) *CreateMetaIDPParams {
	return &CreateMetaIDPParams{
		Context: ctx,
	}
}

// NewCreateMetaIDPParamsWithHTTPClient creates a new CreateMetaIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateMetaIDPParamsWithHTTPClient(client *http.Client) *CreateMetaIDPParams {
	return &CreateMetaIDPParams{
		HTTPClient: client,
	}
}

/*
CreateMetaIDPParams contains all the parameters to send to the API endpoint

	for the create meta ID p operation.

	Typically these are written to a http.Request.
*/
type CreateMetaIDPParams struct {

	/* MetaIDP.

	   MetaIDP
	*/
	MetaIDP *models.MetaIDP

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

// WithDefaults hydrates default values in the create meta ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateMetaIDPParams) WithDefaults() *CreateMetaIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create meta ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateMetaIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateMetaIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create meta ID p params
func (o *CreateMetaIDPParams) WithTimeout(timeout time.Duration) *CreateMetaIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create meta ID p params
func (o *CreateMetaIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create meta ID p params
func (o *CreateMetaIDPParams) WithContext(ctx context.Context) *CreateMetaIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create meta ID p params
func (o *CreateMetaIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create meta ID p params
func (o *CreateMetaIDPParams) WithHTTPClient(client *http.Client) *CreateMetaIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create meta ID p params
func (o *CreateMetaIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMetaIDP adds the metaIDP to the create meta ID p params
func (o *CreateMetaIDPParams) WithMetaIDP(metaIDP *models.MetaIDP) *CreateMetaIDPParams {
	o.SetMetaIDP(metaIDP)
	return o
}

// SetMetaIDP adds the metaIdP to the create meta ID p params
func (o *CreateMetaIDPParams) SetMetaIDP(metaIDP *models.MetaIDP) {
	o.MetaIDP = metaIDP
}

// WithIfMatch adds the ifMatch to the create meta ID p params
func (o *CreateMetaIDPParams) WithIfMatch(ifMatch *string) *CreateMetaIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create meta ID p params
func (o *CreateMetaIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the create meta ID p params
func (o *CreateMetaIDPParams) WithWid(wid string) *CreateMetaIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create meta ID p params
func (o *CreateMetaIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateMetaIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.MetaIDP != nil {
		if err := r.SetBodyParam(o.MetaIDP); err != nil {
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
