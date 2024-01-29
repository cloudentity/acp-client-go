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

// NewUpdateStaticIDPParams creates a new UpdateStaticIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateStaticIDPParams() *UpdateStaticIDPParams {
	return &UpdateStaticIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateStaticIDPParamsWithTimeout creates a new UpdateStaticIDPParams object
// with the ability to set a timeout on a request.
func NewUpdateStaticIDPParamsWithTimeout(timeout time.Duration) *UpdateStaticIDPParams {
	return &UpdateStaticIDPParams{
		timeout: timeout,
	}
}

// NewUpdateStaticIDPParamsWithContext creates a new UpdateStaticIDPParams object
// with the ability to set a context for a request.
func NewUpdateStaticIDPParamsWithContext(ctx context.Context) *UpdateStaticIDPParams {
	return &UpdateStaticIDPParams{
		Context: ctx,
	}
}

// NewUpdateStaticIDPParamsWithHTTPClient creates a new UpdateStaticIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateStaticIDPParamsWithHTTPClient(client *http.Client) *UpdateStaticIDPParams {
	return &UpdateStaticIDPParams{
		HTTPClient: client,
	}
}

/*
UpdateStaticIDPParams contains all the parameters to send to the API endpoint

	for the update static ID p operation.

	Typically these are written to a http.Request.
*/
type UpdateStaticIDPParams struct {

	/* StaticIDP.

	   StaticIDP
	*/
	StaticIDP *models.StaticIDP

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

// WithDefaults hydrates default values in the update static ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateStaticIDPParams) WithDefaults() *UpdateStaticIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update static ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateStaticIDPParams) SetDefaults() {
	var (
		iidDefault = string("default")

		widDefault = string("default")
	)

	val := UpdateStaticIDPParams{
		Iid: iidDefault,
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update static ID p params
func (o *UpdateStaticIDPParams) WithTimeout(timeout time.Duration) *UpdateStaticIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update static ID p params
func (o *UpdateStaticIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update static ID p params
func (o *UpdateStaticIDPParams) WithContext(ctx context.Context) *UpdateStaticIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update static ID p params
func (o *UpdateStaticIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update static ID p params
func (o *UpdateStaticIDPParams) WithHTTPClient(client *http.Client) *UpdateStaticIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update static ID p params
func (o *UpdateStaticIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithStaticIDP adds the staticIDP to the update static ID p params
func (o *UpdateStaticIDPParams) WithStaticIDP(staticIDP *models.StaticIDP) *UpdateStaticIDPParams {
	o.SetStaticIDP(staticIDP)
	return o
}

// SetStaticIDP adds the staticIdP to the update static ID p params
func (o *UpdateStaticIDPParams) SetStaticIDP(staticIDP *models.StaticIDP) {
	o.StaticIDP = staticIDP
}

// WithIfMatch adds the ifMatch to the update static ID p params
func (o *UpdateStaticIDPParams) WithIfMatch(ifMatch *string) *UpdateStaticIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update static ID p params
func (o *UpdateStaticIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the update static ID p params
func (o *UpdateStaticIDPParams) WithIid(iid string) *UpdateStaticIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update static ID p params
func (o *UpdateStaticIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the update static ID p params
func (o *UpdateStaticIDPParams) WithWid(wid string) *UpdateStaticIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the update static ID p params
func (o *UpdateStaticIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateStaticIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.StaticIDP != nil {
		if err := r.SetBodyParam(o.StaticIDP); err != nil {
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
