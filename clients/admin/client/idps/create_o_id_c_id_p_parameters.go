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

// NewCreateOIDCIDPParams creates a new CreateOIDCIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateOIDCIDPParams() *CreateOIDCIDPParams {
	return &CreateOIDCIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateOIDCIDPParamsWithTimeout creates a new CreateOIDCIDPParams object
// with the ability to set a timeout on a request.
func NewCreateOIDCIDPParamsWithTimeout(timeout time.Duration) *CreateOIDCIDPParams {
	return &CreateOIDCIDPParams{
		timeout: timeout,
	}
}

// NewCreateOIDCIDPParamsWithContext creates a new CreateOIDCIDPParams object
// with the ability to set a context for a request.
func NewCreateOIDCIDPParamsWithContext(ctx context.Context) *CreateOIDCIDPParams {
	return &CreateOIDCIDPParams{
		Context: ctx,
	}
}

// NewCreateOIDCIDPParamsWithHTTPClient creates a new CreateOIDCIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateOIDCIDPParamsWithHTTPClient(client *http.Client) *CreateOIDCIDPParams {
	return &CreateOIDCIDPParams{
		HTTPClient: client,
	}
}

/*
CreateOIDCIDPParams contains all the parameters to send to the API endpoint

	for the create o ID c ID p operation.

	Typically these are written to a http.Request.
*/
type CreateOIDCIDPParams struct {

	/* OIDCIDP.

	   OIDCIDP
	*/
	OIDCIDP *models.OIDCIDP

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

// WithDefaults hydrates default values in the create o ID c ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateOIDCIDPParams) WithDefaults() *CreateOIDCIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create o ID c ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateOIDCIDPParams) SetDefaults() {
	var (
		widDefault = string("default")
	)

	val := CreateOIDCIDPParams{
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create o ID c ID p params
func (o *CreateOIDCIDPParams) WithTimeout(timeout time.Duration) *CreateOIDCIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create o ID c ID p params
func (o *CreateOIDCIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create o ID c ID p params
func (o *CreateOIDCIDPParams) WithContext(ctx context.Context) *CreateOIDCIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create o ID c ID p params
func (o *CreateOIDCIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create o ID c ID p params
func (o *CreateOIDCIDPParams) WithHTTPClient(client *http.Client) *CreateOIDCIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create o ID c ID p params
func (o *CreateOIDCIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithOIDCIDP adds the oIDCIDP to the create o ID c ID p params
func (o *CreateOIDCIDPParams) WithOIDCIDP(oIDCIDP *models.OIDCIDP) *CreateOIDCIDPParams {
	o.SetOIDCIDP(oIDCIDP)
	return o
}

// SetOIDCIDP adds the oIdCIdP to the create o ID c ID p params
func (o *CreateOIDCIDPParams) SetOIDCIDP(oIDCIDP *models.OIDCIDP) {
	o.OIDCIDP = oIDCIDP
}

// WithIfMatch adds the ifMatch to the create o ID c ID p params
func (o *CreateOIDCIDPParams) WithIfMatch(ifMatch *string) *CreateOIDCIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the create o ID c ID p params
func (o *CreateOIDCIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithWid adds the wid to the create o ID c ID p params
func (o *CreateOIDCIDPParams) WithWid(wid string) *CreateOIDCIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the create o ID c ID p params
func (o *CreateOIDCIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateOIDCIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.OIDCIDP != nil {
		if err := r.SetBodyParam(o.OIDCIDP); err != nil {
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
