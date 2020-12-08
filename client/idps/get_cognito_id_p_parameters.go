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

// NewGetCognitoIDPParams creates a new GetCognitoIDPParams object
// with the default values initialized.
func NewGetCognitoIDPParams() *GetCognitoIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetCognitoIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewGetCognitoIDPParamsWithTimeout creates a new GetCognitoIDPParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetCognitoIDPParamsWithTimeout(timeout time.Duration) *GetCognitoIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetCognitoIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,

		timeout: timeout,
	}
}

// NewGetCognitoIDPParamsWithContext creates a new GetCognitoIDPParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetCognitoIDPParamsWithContext(ctx context.Context) *GetCognitoIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetCognitoIDPParams{
		Aid: aidDefault,
		Tid: tidDefault,

		Context: ctx,
	}
}

// NewGetCognitoIDPParamsWithHTTPClient creates a new GetCognitoIDPParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetCognitoIDPParamsWithHTTPClient(client *http.Client) *GetCognitoIDPParams {
	var (
		aidDefault = string("default")
		tidDefault = string("default")
	)
	return &GetCognitoIDPParams{
		Aid:        aidDefault,
		Tid:        tidDefault,
		HTTPClient: client,
	}
}

/*GetCognitoIDPParams contains all the parameters to send to the API endpoint
for the get cognito ID p operation typically these are written to a http.Request
*/
type GetCognitoIDPParams struct {

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

// WithTimeout adds the timeout to the get cognito ID p params
func (o *GetCognitoIDPParams) WithTimeout(timeout time.Duration) *GetCognitoIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get cognito ID p params
func (o *GetCognitoIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get cognito ID p params
func (o *GetCognitoIDPParams) WithContext(ctx context.Context) *GetCognitoIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get cognito ID p params
func (o *GetCognitoIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get cognito ID p params
func (o *GetCognitoIDPParams) WithHTTPClient(client *http.Client) *GetCognitoIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get cognito ID p params
func (o *GetCognitoIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAid adds the aid to the get cognito ID p params
func (o *GetCognitoIDPParams) WithAid(aid string) *GetCognitoIDPParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the get cognito ID p params
func (o *GetCognitoIDPParams) SetAid(aid string) {
	o.Aid = aid
}

// WithIid adds the iid to the get cognito ID p params
func (o *GetCognitoIDPParams) WithIid(iid string) *GetCognitoIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the get cognito ID p params
func (o *GetCognitoIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithTid adds the tid to the get cognito ID p params
func (o *GetCognitoIDPParams) WithTid(tid string) *GetCognitoIDPParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get cognito ID p params
func (o *GetCognitoIDPParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *GetCognitoIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
