// Code generated by go-swagger; DO NOT EDIT.

package clients

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

// NewUpdateClientForDeveloperParams creates a new UpdateClientForDeveloperParams object
// with the default values initialized.
func NewUpdateClientForDeveloperParams() *UpdateClientForDeveloperParams {
	var (
		aidDefault = string("developer")
		cidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateClientForDeveloperParams{
		Aid: aidDefault,
		Cid: cidDefault,
		Tid: tidDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateClientForDeveloperParamsWithTimeout creates a new UpdateClientForDeveloperParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewUpdateClientForDeveloperParamsWithTimeout(timeout time.Duration) *UpdateClientForDeveloperParams {
	var (
		aidDefault = string("developer")
		cidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateClientForDeveloperParams{
		Aid: aidDefault,
		Cid: cidDefault,
		Tid: tidDefault,

		timeout: timeout,
	}
}

// NewUpdateClientForDeveloperParamsWithContext creates a new UpdateClientForDeveloperParams object
// with the default values initialized, and the ability to set a context for a request
func NewUpdateClientForDeveloperParamsWithContext(ctx context.Context) *UpdateClientForDeveloperParams {
	var (
		aidDefault = string("developer")
		cidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateClientForDeveloperParams{
		Aid: aidDefault,
		Cid: cidDefault,
		Tid: tidDefault,

		Context: ctx,
	}
}

// NewUpdateClientForDeveloperParamsWithHTTPClient creates a new UpdateClientForDeveloperParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewUpdateClientForDeveloperParamsWithHTTPClient(client *http.Client) *UpdateClientForDeveloperParams {
	var (
		aidDefault = string("developer")
		cidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateClientForDeveloperParams{
		Aid:        aidDefault,
		Cid:        cidDefault,
		Tid:        tidDefault,
		HTTPClient: client,
	}
}

/*UpdateClientForDeveloperParams contains all the parameters to send to the API endpoint
for the update client for developer operation typically these are written to a http.Request
*/
type UpdateClientForDeveloperParams struct {

	/*Client*/
	Client *models.UpdateClientDeveloperRequest
	/*Aid
	  Developer server id

	*/
	Aid string
	/*Cid
	  Client id

	*/
	Cid string
	/*Tid
	  Tenant id

	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the update client for developer params
func (o *UpdateClientForDeveloperParams) WithTimeout(timeout time.Duration) *UpdateClientForDeveloperParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update client for developer params
func (o *UpdateClientForDeveloperParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update client for developer params
func (o *UpdateClientForDeveloperParams) WithContext(ctx context.Context) *UpdateClientForDeveloperParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update client for developer params
func (o *UpdateClientForDeveloperParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update client for developer params
func (o *UpdateClientForDeveloperParams) WithHTTPClient(client *http.Client) *UpdateClientForDeveloperParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update client for developer params
func (o *UpdateClientForDeveloperParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithClient adds the client to the update client for developer params
func (o *UpdateClientForDeveloperParams) WithClient(client *models.UpdateClientDeveloperRequest) *UpdateClientForDeveloperParams {
	o.SetClient(client)
	return o
}

// SetClient adds the client to the update client for developer params
func (o *UpdateClientForDeveloperParams) SetClient(client *models.UpdateClientDeveloperRequest) {
	o.Client = client
}

// WithAid adds the aid to the update client for developer params
func (o *UpdateClientForDeveloperParams) WithAid(aid string) *UpdateClientForDeveloperParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the update client for developer params
func (o *UpdateClientForDeveloperParams) SetAid(aid string) {
	o.Aid = aid
}

// WithCid adds the cid to the update client for developer params
func (o *UpdateClientForDeveloperParams) WithCid(cid string) *UpdateClientForDeveloperParams {
	o.SetCid(cid)
	return o
}

// SetCid adds the cid to the update client for developer params
func (o *UpdateClientForDeveloperParams) SetCid(cid string) {
	o.Cid = cid
}

// WithTid adds the tid to the update client for developer params
func (o *UpdateClientForDeveloperParams) WithTid(tid string) *UpdateClientForDeveloperParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the update client for developer params
func (o *UpdateClientForDeveloperParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateClientForDeveloperParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Client != nil {
		if err := r.SetBodyParam(o.Client); err != nil {
			return err
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	// path param cid
	if err := r.SetPathParam("cid", o.Cid); err != nil {
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
