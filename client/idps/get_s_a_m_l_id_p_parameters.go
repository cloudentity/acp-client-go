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
)

// NewGetSAMLIDPParams creates a new GetSAMLIDPParams object
// with the default values initialized.
func NewGetSAMLIDPParams() *GetSAMLIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetSAMLIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewGetSAMLIDPParamsWithTimeout creates a new GetSAMLIDPParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetSAMLIDPParamsWithTimeout(timeout time.Duration) *GetSAMLIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetSAMLIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: timeout,
	}
}

// NewGetSAMLIDPParamsWithContext creates a new GetSAMLIDPParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetSAMLIDPParamsWithContext(ctx context.Context) *GetSAMLIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetSAMLIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,

		Context: ctx,
	}
}

// NewGetSAMLIDPParamsWithHTTPClient creates a new GetSAMLIDPParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetSAMLIDPParamsWithHTTPClient(client *http.Client) *GetSAMLIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetSAMLIDPParams{
		Aid:        aidDefault,
		Tid:        tidDefault,
		HTTPClient: client,
	}
}

/*GetSAMLIDPParams contains all the parameters to send to the API endpoint
for the get s a m l ID p operation typically these are written to a http.Request
*/
type GetSAMLIDPParams struct {

	/*Aid
	  Authorization server id

	*/
	Aid string
	/*Iid
	  IDP id

	*/
	Iid string
	/*Tid
	  Tenant id

	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithTimeout(timeout time.Duration) *GetSAMLIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithContext(ctx context.Context) *GetSAMLIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithHTTPClient(client *http.Client) *GetSAMLIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithAid(aid string) *GetSAMLIDPParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetAid(aid string) {
	o.Aid = aid
}

// WithIid adds the iid to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithIid(iid string) *GetSAMLIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithTid adds the tid to the get s a m l ID p params
func (o *GetSAMLIDPParams) WithTid(tid string) *GetSAMLIDPParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get s a m l ID p params
func (o *GetSAMLIDPParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *GetSAMLIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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
