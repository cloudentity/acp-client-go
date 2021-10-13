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

	"github.com/cloudentity/acp-client-go/acp/models"
)

// NewCreateSAMLIDPParams creates a new CreateSAMLIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateSAMLIDPParams() *CreateSAMLIDPParams {
	return &CreateSAMLIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateSAMLIDPParamsWithTimeout creates a new CreateSAMLIDPParams object
// with the ability to set a timeout on a request.
func NewCreateSAMLIDPParamsWithTimeout(timeout time.Duration) *CreateSAMLIDPParams {
	return &CreateSAMLIDPParams{
		timeout: timeout,
	}
}

// NewCreateSAMLIDPParamsWithContext creates a new CreateSAMLIDPParams object
// with the ability to set a context for a request.
func NewCreateSAMLIDPParamsWithContext(ctx context.Context) *CreateSAMLIDPParams {
	return &CreateSAMLIDPParams{
		Context: ctx,
	}
}

// NewCreateSAMLIDPParamsWithHTTPClient creates a new CreateSAMLIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateSAMLIDPParamsWithHTTPClient(client *http.Client) *CreateSAMLIDPParams {
	return &CreateSAMLIDPParams{
		HTTPClient: client,
	}
}

/* CreateSAMLIDPParams contains all the parameters to send to the API endpoint
   for the create s a m l ID p operation.

   Typically these are written to a http.Request.
*/
type CreateSAMLIDPParams struct {

	/* SAMLIDP.

	   SAMLIDP
	*/
	SAMLIDP *models.SAMLIDP

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* Tid.

	   Tenant id

	   Default: "default"
	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create s a m l ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSAMLIDPParams) WithDefaults() *CreateSAMLIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create s a m l ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSAMLIDPParams) SetDefaults() {
	var (
		aidDefault = string("default")

		tidDefault = string("default")
	)

	val := CreateSAMLIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the create s a m l ID p params
func (o *CreateSAMLIDPParams) WithTimeout(timeout time.Duration) *CreateSAMLIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create s a m l ID p params
func (o *CreateSAMLIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create s a m l ID p params
func (o *CreateSAMLIDPParams) WithContext(ctx context.Context) *CreateSAMLIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create s a m l ID p params
func (o *CreateSAMLIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create s a m l ID p params
func (o *CreateSAMLIDPParams) WithHTTPClient(client *http.Client) *CreateSAMLIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create s a m l ID p params
func (o *CreateSAMLIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSAMLIDP adds the sAMLIDP to the create s a m l ID p params
func (o *CreateSAMLIDPParams) WithSAMLIDP(sAMLIDP *models.SAMLIDP) *CreateSAMLIDPParams {
	o.SetSAMLIDP(sAMLIDP)
	return o
}

// SetSAMLIDP adds the sAMLIdP to the create s a m l ID p params
func (o *CreateSAMLIDPParams) SetSAMLIDP(sAMLIDP *models.SAMLIDP) {
	o.SAMLIDP = sAMLIDP
}

// WithAid adds the aid to the create s a m l ID p params
func (o *CreateSAMLIDPParams) WithAid(aid string) *CreateSAMLIDPParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the create s a m l ID p params
func (o *CreateSAMLIDPParams) SetAid(aid string) {
	o.Aid = aid
}

// WithTid adds the tid to the create s a m l ID p params
func (o *CreateSAMLIDPParams) WithTid(tid string) *CreateSAMLIDPParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the create s a m l ID p params
func (o *CreateSAMLIDPParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *CreateSAMLIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.SAMLIDP != nil {
		if err := r.SetBodyParam(o.SAMLIDP); err != nil {
			return err
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
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