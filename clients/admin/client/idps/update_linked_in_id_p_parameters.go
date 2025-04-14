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

// NewUpdateLinkedInIDPParams creates a new UpdateLinkedInIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateLinkedInIDPParams() *UpdateLinkedInIDPParams {
	return &UpdateLinkedInIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateLinkedInIDPParamsWithTimeout creates a new UpdateLinkedInIDPParams object
// with the ability to set a timeout on a request.
func NewUpdateLinkedInIDPParamsWithTimeout(timeout time.Duration) *UpdateLinkedInIDPParams {
	return &UpdateLinkedInIDPParams{
		timeout: timeout,
	}
}

// NewUpdateLinkedInIDPParamsWithContext creates a new UpdateLinkedInIDPParams object
// with the ability to set a context for a request.
func NewUpdateLinkedInIDPParamsWithContext(ctx context.Context) *UpdateLinkedInIDPParams {
	return &UpdateLinkedInIDPParams{
		Context: ctx,
	}
}

// NewUpdateLinkedInIDPParamsWithHTTPClient creates a new UpdateLinkedInIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateLinkedInIDPParamsWithHTTPClient(client *http.Client) *UpdateLinkedInIDPParams {
	return &UpdateLinkedInIDPParams{
		HTTPClient: client,
	}
}

/*
UpdateLinkedInIDPParams contains all the parameters to send to the API endpoint

	for the update linked in ID p operation.

	Typically these are written to a http.Request.
*/
type UpdateLinkedInIDPParams struct {

	/* LinkedInIDP.

	   LinkedInIDP
	*/
	LinkedInIDP *models.LinkedInIDP

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

// WithDefaults hydrates default values in the update linked in ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateLinkedInIDPParams) WithDefaults() *UpdateLinkedInIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update linked in ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateLinkedInIDPParams) SetDefaults() {
	var (
		iidDefault = string("default")

		widDefault = string("default")
	)

	val := UpdateLinkedInIDPParams{
		Iid: iidDefault,
		Wid: widDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) WithTimeout(timeout time.Duration) *UpdateLinkedInIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) WithContext(ctx context.Context) *UpdateLinkedInIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) WithHTTPClient(client *http.Client) *UpdateLinkedInIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLinkedInIDP adds the linkedInIDP to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) WithLinkedInIDP(linkedInIDP *models.LinkedInIDP) *UpdateLinkedInIDPParams {
	o.SetLinkedInIDP(linkedInIDP)
	return o
}

// SetLinkedInIDP adds the linkedInIdP to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) SetLinkedInIDP(linkedInIDP *models.LinkedInIDP) {
	o.LinkedInIDP = linkedInIDP
}

// WithIfMatch adds the ifMatch to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) WithIfMatch(ifMatch *string) *UpdateLinkedInIDPParams {
	o.SetIfMatch(ifMatch)
	return o
}

// SetIfMatch adds the ifMatch to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) SetIfMatch(ifMatch *string) {
	o.IfMatch = ifMatch
}

// WithIid adds the iid to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) WithIid(iid string) *UpdateLinkedInIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithWid adds the wid to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) WithWid(wid string) *UpdateLinkedInIDPParams {
	o.SetWid(wid)
	return o
}

// SetWid adds the wid to the update linked in ID p params
func (o *UpdateLinkedInIDPParams) SetWid(wid string) {
	o.Wid = wid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateLinkedInIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.LinkedInIDP != nil {
		if err := r.SetBodyParam(o.LinkedInIDP); err != nil {
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
