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

	"github.com/cloudentity/acp-client-go/models"
)

// NewUpdateCustomIDPParams creates a new UpdateCustomIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateCustomIDPParams() *UpdateCustomIDPParams {
	return &UpdateCustomIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateCustomIDPParamsWithTimeout creates a new UpdateCustomIDPParams object
// with the ability to set a timeout on a request.
func NewUpdateCustomIDPParamsWithTimeout(timeout time.Duration) *UpdateCustomIDPParams {
	return &UpdateCustomIDPParams{
		timeout: timeout,
	}
}

// NewUpdateCustomIDPParamsWithContext creates a new UpdateCustomIDPParams object
// with the ability to set a context for a request.
func NewUpdateCustomIDPParamsWithContext(ctx context.Context) *UpdateCustomIDPParams {
	return &UpdateCustomIDPParams{
		Context: ctx,
	}
}

// NewUpdateCustomIDPParamsWithHTTPClient creates a new UpdateCustomIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateCustomIDPParamsWithHTTPClient(client *http.Client) *UpdateCustomIDPParams {
	return &UpdateCustomIDPParams{
		HTTPClient: client,
	}
}

/* UpdateCustomIDPParams contains all the parameters to send to the API endpoint
   for the update custom ID p operation.

   Typically these are written to a http.Request.
*/
type UpdateCustomIDPParams struct {

	/* CustomIDP.

	   CustomIDP
	*/
	CustomIDP *models.CustomIDP

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Iid.

	   IDP id

	   Default: "default"
	*/
	Iid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update custom ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateCustomIDPParams) WithDefaults() *UpdateCustomIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update custom ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateCustomIDPParams) SetDefaults() {
	var (
		aidDefault = string("default")

		iidDefault = string("default")

		tidDefault = string("default")
	)

	val := UpdateCustomIDPParams{
		Aid: aidDefault,
		Iid: iidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update custom ID p params
func (o *UpdateCustomIDPParams) WithTimeout(timeout time.Duration) *UpdateCustomIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update custom ID p params
func (o *UpdateCustomIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update custom ID p params
func (o *UpdateCustomIDPParams) WithContext(ctx context.Context) *UpdateCustomIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update custom ID p params
func (o *UpdateCustomIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update custom ID p params
func (o *UpdateCustomIDPParams) WithHTTPClient(client *http.Client) *UpdateCustomIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update custom ID p params
func (o *UpdateCustomIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCustomIDP adds the customIDP to the update custom ID p params
func (o *UpdateCustomIDPParams) WithCustomIDP(customIDP *models.CustomIDP) *UpdateCustomIDPParams {
	o.SetCustomIDP(customIDP)
	return o
}

// SetCustomIDP adds the customIdP to the update custom ID p params
func (o *UpdateCustomIDPParams) SetCustomIDP(customIDP *models.CustomIDP) {
	o.CustomIDP = customIDP
}

// WithAid adds the aid to the update custom ID p params
func (o *UpdateCustomIDPParams) WithAid(aid string) *UpdateCustomIDPParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the update custom ID p params
func (o *UpdateCustomIDPParams) SetAid(aid string) {
	o.Aid = aid
}

// WithIid adds the iid to the update custom ID p params
func (o *UpdateCustomIDPParams) WithIid(iid string) *UpdateCustomIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update custom ID p params
func (o *UpdateCustomIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithTid adds the tid to the update custom ID p params
func (o *UpdateCustomIDPParams) WithTid(tid string) *UpdateCustomIDPParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the update custom ID p params
func (o *UpdateCustomIDPParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateCustomIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.CustomIDP != nil {
		if err := r.SetBodyParam(o.CustomIDP); err != nil {
			return err
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param iid
	if err := r.SetPathParam("iid", o.Iid); err != nil {
		return err
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
