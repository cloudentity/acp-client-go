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

// NewUpdateCognitoIDPParams creates a new UpdateCognitoIDPParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateCognitoIDPParams() *UpdateCognitoIDPParams {
	return &UpdateCognitoIDPParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateCognitoIDPParamsWithTimeout creates a new UpdateCognitoIDPParams object
// with the ability to set a timeout on a request.
func NewUpdateCognitoIDPParamsWithTimeout(timeout time.Duration) *UpdateCognitoIDPParams {
	return &UpdateCognitoIDPParams{
		timeout: timeout,
	}
}

// NewUpdateCognitoIDPParamsWithContext creates a new UpdateCognitoIDPParams object
// with the ability to set a context for a request.
func NewUpdateCognitoIDPParamsWithContext(ctx context.Context) *UpdateCognitoIDPParams {
	return &UpdateCognitoIDPParams{
		Context: ctx,
	}
}

// NewUpdateCognitoIDPParamsWithHTTPClient creates a new UpdateCognitoIDPParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateCognitoIDPParamsWithHTTPClient(client *http.Client) *UpdateCognitoIDPParams {
	return &UpdateCognitoIDPParams{
		HTTPClient: client,
	}
}

/* UpdateCognitoIDPParams contains all the parameters to send to the API endpoint
   for the update cognito ID p operation.

   Typically these are written to a http.Request.
*/
type UpdateCognitoIDPParams struct {

	/* CognitoIDP.

	   CognitoIDP
	*/
	CognitoIDP *models.CognitoIDP

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

// WithDefaults hydrates default values in the update cognito ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateCognitoIDPParams) WithDefaults() *UpdateCognitoIDPParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update cognito ID p params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateCognitoIDPParams) SetDefaults() {
	var (
		aidDefault = string("default")

		iidDefault = string("default")

		tidDefault = string("default")
	)

	val := UpdateCognitoIDPParams{
		Aid: aidDefault,
		Iid: iidDefault,
		Tid: tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the update cognito ID p params
func (o *UpdateCognitoIDPParams) WithTimeout(timeout time.Duration) *UpdateCognitoIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update cognito ID p params
func (o *UpdateCognitoIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update cognito ID p params
func (o *UpdateCognitoIDPParams) WithContext(ctx context.Context) *UpdateCognitoIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update cognito ID p params
func (o *UpdateCognitoIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update cognito ID p params
func (o *UpdateCognitoIDPParams) WithHTTPClient(client *http.Client) *UpdateCognitoIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update cognito ID p params
func (o *UpdateCognitoIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCognitoIDP adds the cognitoIDP to the update cognito ID p params
func (o *UpdateCognitoIDPParams) WithCognitoIDP(cognitoIDP *models.CognitoIDP) *UpdateCognitoIDPParams {
	o.SetCognitoIDP(cognitoIDP)
	return o
}

// SetCognitoIDP adds the cognitoIdP to the update cognito ID p params
func (o *UpdateCognitoIDPParams) SetCognitoIDP(cognitoIDP *models.CognitoIDP) {
	o.CognitoIDP = cognitoIDP
}

// WithAid adds the aid to the update cognito ID p params
func (o *UpdateCognitoIDPParams) WithAid(aid string) *UpdateCognitoIDPParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the update cognito ID p params
func (o *UpdateCognitoIDPParams) SetAid(aid string) {
	o.Aid = aid
}

// WithIid adds the iid to the update cognito ID p params
func (o *UpdateCognitoIDPParams) WithIid(iid string) *UpdateCognitoIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update cognito ID p params
func (o *UpdateCognitoIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithTid adds the tid to the update cognito ID p params
func (o *UpdateCognitoIDPParams) WithTid(tid string) *UpdateCognitoIDPParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the update cognito ID p params
func (o *UpdateCognitoIDPParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateCognitoIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.CognitoIDP != nil {
		if err := r.SetBodyParam(o.CognitoIDP); err != nil {
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