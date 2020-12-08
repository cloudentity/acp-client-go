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

// NewUpdateOIDCIDPParams creates a new UpdateOIDCIDPParams object
// with the default values initialized.
func NewUpdateOIDCIDPParams() *UpdateOIDCIDPParams {
	var (
		aidDefault = string("default")
		iidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateOIDCIDPParams{
		Aid: aidDefault,
		Iid: iidDefault,
		Tid: tidDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateOIDCIDPParamsWithTimeout creates a new UpdateOIDCIDPParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewUpdateOIDCIDPParamsWithTimeout(timeout time.Duration) *UpdateOIDCIDPParams {
	var (
		aidDefault = string("default")
		iidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateOIDCIDPParams{
		Aid: aidDefault,
		Iid: iidDefault,
		Tid: tidDefault,

		timeout: timeout,
	}
}

// NewUpdateOIDCIDPParamsWithContext creates a new UpdateOIDCIDPParams object
// with the default values initialized, and the ability to set a context for a request
func NewUpdateOIDCIDPParamsWithContext(ctx context.Context) *UpdateOIDCIDPParams {
	var (
		aidDefault = string("default")
		iidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateOIDCIDPParams{
		Aid: aidDefault,
		Iid: iidDefault,
		Tid: tidDefault,

		Context: ctx,
	}
}

// NewUpdateOIDCIDPParamsWithHTTPClient creates a new UpdateOIDCIDPParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewUpdateOIDCIDPParamsWithHTTPClient(client *http.Client) *UpdateOIDCIDPParams {
	var (
		aidDefault = string("default")
		iidDefault = string("default")
		tidDefault = string("default")
	)
	return &UpdateOIDCIDPParams{
		Aid:        aidDefault,
		Iid:        iidDefault,
		Tid:        tidDefault,
		HTTPClient: client,
	}
}

/*UpdateOIDCIDPParams contains all the parameters to send to the API endpoint
for the update o ID c ID p operation typically these are written to a http.Request
*/
type UpdateOIDCIDPParams struct {

	/*OIDCIDP
	  OIDCIDP

	*/
	OIDCIDP *models.OIDCIDP
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

// WithTimeout adds the timeout to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) WithTimeout(timeout time.Duration) *UpdateOIDCIDPParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) WithContext(ctx context.Context) *UpdateOIDCIDPParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) WithHTTPClient(client *http.Client) *UpdateOIDCIDPParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithOIDCIDP adds the oIDCIDP to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) WithOIDCIDP(oIDCIDP *models.OIDCIDP) *UpdateOIDCIDPParams {
	o.SetOIDCIDP(oIDCIDP)
	return o
}

// SetOIDCIDP adds the oIdCIdP to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) SetOIDCIDP(oIDCIDP *models.OIDCIDP) {
	o.OIDCIDP = oIDCIDP
}

// WithAid adds the aid to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) WithAid(aid string) *UpdateOIDCIDPParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) SetAid(aid string) {
	o.Aid = aid
}

// WithIid adds the iid to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) WithIid(iid string) *UpdateOIDCIDPParams {
	o.SetIid(iid)
	return o
}

// SetIid adds the iid to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) SetIid(iid string) {
	o.Iid = iid
}

// WithTid adds the tid to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) WithTid(tid string) *UpdateOIDCIDPParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the update o ID c ID p params
func (o *UpdateOIDCIDPParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateOIDCIDPParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.OIDCIDP != nil {
		if err := r.SetBodyParam(o.OIDCIDP); err != nil {
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
