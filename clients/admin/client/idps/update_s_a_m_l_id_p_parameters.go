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

// NewUpdateSAMLIDPParams creates a new UpdateSAMLIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateSAMLIDPParams() *UpdateSAMLIDPParams {
	return &UpdateSAMLIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateSAMLIDPParamsWithTimeout creates a new UpdateSAMLIDPParams object
// with the ability to set a timeout on a request.
func NewUpdateSAMLIDPParamsWithTimeout(timeout time.Duration) *UpdateSAMLIDPParams {
	return &UpdateSAMLIDPParams{
		timeout: timeout,
	}
}

// NewUpdateSAMLIDPParamsWithContext creates a new UpdateSAMLIDPParams object
// with the ability to set a context for a request.
func NewUpdateSAMLIDPParamsWithContext(ctx context.Context) *UpdateSAMLIDPParams {
	return &UpdateSAMLIDPParams{
		Context: ctx,
	}
}

// NewUpdateSAMLIDPParamsWithHTTPClient creates a new UpdateSAMLIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateSAMLIDPParamsWithHTTPClient(client *http.Client) *UpdateSAMLIDPParams {
	return &UpdateSAMLIDPParams{
		HTTPClient: client,
	}
}

/*
UpdateSAMLIDPParams contains all the parameters to send to the API endpoint

	for the update s a m l ID p operation.

	Typically these are written to a http.Request.
*/
type UpdateSAMLIDPParams struct {

	/* SAMLIDP.

	   SAMLIDP
	*/
	SAMLIDP *models.SAMLIDP

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

// WithDefaults hydrates default values in the update s a m l ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateSAMLIDPParams) WithDefaults() *UpdateSAMLIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update s a m l ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateSAMLIDPParams) SetDefaults() {
	var (
		iidDefault = string("default")

		widDefault = string("default")
	)

	val := UpdateSAMLIDPParams{
		Iid: iidDefault,
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) WithTimeout(timeout time.Duration) *UpdateSAMLIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) WithContext(ctx context.Context) *UpdateSAMLIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) WithHTTPClient(client *http.Client) *UpdateSAMLIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSAMLIDP adds the sAMLIDP to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) WithSAMLIDP(sAMLIDP *models.SAMLIDP) *UpdateSAMLIDPParams {
	o.SetSAMLIDP(sAMLIDP)
	return o
}

// SetSAMLIDP adds the sAMLIdP to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) SetSAMLIDP(sAMLIDP *models.SAMLIDP) {
	o.SAMLIDP = sAMLIDP
}

// WithIfMatch adds the ifMatch to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) WithIfMatch(ifMatch *string) *UpdateSAMLIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) WithIid(iid string) *UpdateSAMLIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) WithWid(wid string) *UpdateSAMLIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the update s a m l ID p params
func (o *UpdateSAMLIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateSAMLIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.SAMLIDP != nil {
		if err := r.SetBodyParam(o.SAMLIDP); err != nil {
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
