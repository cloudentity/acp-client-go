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

// NewUpdateMicrosoftIDPParams creates a new UpdateMicrosoftIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateMicrosoftIDPParams() *UpdateMicrosoftIDPParams {
	return &UpdateMicrosoftIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateMicrosoftIDPParamsWithTimeout creates a new UpdateMicrosoftIDPParams object
// with the ability to set a timeout on a request.
func NewUpdateMicrosoftIDPParamsWithTimeout(timeout time.Duration) *UpdateMicrosoftIDPParams {
	return &UpdateMicrosoftIDPParams{
		timeout: timeout,
	}
}

// NewUpdateMicrosoftIDPParamsWithContext creates a new UpdateMicrosoftIDPParams object
// with the ability to set a context for a request.
func NewUpdateMicrosoftIDPParamsWithContext(ctx context.Context) *UpdateMicrosoftIDPParams {
	return &UpdateMicrosoftIDPParams{
		Context: ctx,
	}
}

// NewUpdateMicrosoftIDPParamsWithHTTPClient creates a new UpdateMicrosoftIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateMicrosoftIDPParamsWithHTTPClient(client *http.Client) *UpdateMicrosoftIDPParams {
	return &UpdateMicrosoftIDPParams{
		HTTPClient: client,
	}
}

/*
UpdateMicrosoftIDPParams contains all the parameters to send to the API endpoint

	for the update microsoft ID p operation.

	Typically these are written to a http.Request.
*/
type UpdateMicrosoftIDPParams struct {

	/* MicrosoftIDP.

	   MicrosoftIDP
	*/
	MicrosoftIDP *models.MicrosoftIDP

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

// WithDefaults hydrates default values in the update microsoft ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateMicrosoftIDPParams) WithDefaults() *UpdateMicrosoftIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update microsoft ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateMicrosoftIDPParams) SetDefaults() {
	var (
		iidDefault = string("default")

		widDefault = string("default")
	)

	val := UpdateMicrosoftIDPParams{
		Iid: iidDefault,
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) WithTimeout(timeout time.Duration) *UpdateMicrosoftIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) WithContext(ctx context.Context) *UpdateMicrosoftIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) WithHTTPClient(client *http.Client) *UpdateMicrosoftIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMicrosoftIDP adds the microsoftIDP to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) WithMicrosoftIDP(microsoftIDP *models.MicrosoftIDP) *UpdateMicrosoftIDPParams {
	o.SetMicrosoftIDP(microsoftIDP)
	return o
}

// SetMicrosoftIDP adds the microsoftIdP to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) SetMicrosoftIDP(microsoftIDP *models.MicrosoftIDP) {
	o.MicrosoftIDP = microsoftIDP
}

// WithIfMatch adds the ifMatch to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) WithIfMatch(ifMatch *string) *UpdateMicrosoftIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) WithIid(iid string) *UpdateMicrosoftIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) WithWid(wid string) *UpdateMicrosoftIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the update microsoft ID p params
func (o *UpdateMicrosoftIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateMicrosoftIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.MicrosoftIDP != nil {
		if err := r.SetBodyParam(o.MicrosoftIDP); err != nil {
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
