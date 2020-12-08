// Code generated by go-swagger; DO NOT EDIT.

package consents

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

// NewUpdateConsentActionParams creates a new UpdateConsentActionParams object
// with the default values initialized.
func NewUpdateConsentActionParams() *UpdateConsentActionParams {
	var (
		tidDefault = string("default")
	)
	return &UpdateConsentActionParams{
		Tid: tidDefault,

		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateConsentActionParamsWithTimeout creates a new UpdateConsentActionParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewUpdateConsentActionParamsWithTimeout(timeout time.Duration) *UpdateConsentActionParams {
	var (
		tidDefault = string("default")
	)
	return &UpdateConsentActionParams{
		Tid: tidDefault,

		timeout: timeout,
	}
}

// NewUpdateConsentActionParamsWithContext creates a new UpdateConsentActionParams object
// with the default values initialized, and the ability to set a context for a request
func NewUpdateConsentActionParamsWithContext(ctx context.Context) *UpdateConsentActionParams {
	var (
		tidDefault = string("default")
	)
	return &UpdateConsentActionParams{
		Tid: tidDefault,

		Context: ctx,
	}
}

// NewUpdateConsentActionParamsWithHTTPClient creates a new UpdateConsentActionParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewUpdateConsentActionParamsWithHTTPClient(client *http.Client) *UpdateConsentActionParams {
	var (
		tidDefault = string("default")
	)
	return &UpdateConsentActionParams{
		Tid:        tidDefault,
		HTTPClient: client,
	}
}

/*UpdateConsentActionParams contains all the parameters to send to the API endpoint
for the update consent action operation typically these are written to a http.Request
*/
type UpdateConsentActionParams struct {

	/*ConsentAction*/
	ConsentAction *models.ConsentActionWithConsents
	/*Action*/
	Action string
	/*Tid
	  Tenant id

	*/
	Tid string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the update consent action params
func (o *UpdateConsentActionParams) WithTimeout(timeout time.Duration) *UpdateConsentActionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update consent action params
func (o *UpdateConsentActionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update consent action params
func (o *UpdateConsentActionParams) WithContext(ctx context.Context) *UpdateConsentActionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update consent action params
func (o *UpdateConsentActionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update consent action params
func (o *UpdateConsentActionParams) WithHTTPClient(client *http.Client) *UpdateConsentActionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update consent action params
func (o *UpdateConsentActionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConsentAction adds the consentAction to the update consent action params
func (o *UpdateConsentActionParams) WithConsentAction(consentAction *models.ConsentActionWithConsents) *UpdateConsentActionParams {
	o.SetConsentAction(consentAction)
	return o
}

// SetConsentAction adds the consentAction to the update consent action params
func (o *UpdateConsentActionParams) SetConsentAction(consentAction *models.ConsentActionWithConsents) {
	o.ConsentAction = consentAction
}

// WithAction adds the action to the update consent action params
func (o *UpdateConsentActionParams) WithAction(action string) *UpdateConsentActionParams {
	o.SetAction(action)
	return o
}

// SetAction adds the action to the update consent action params
func (o *UpdateConsentActionParams) SetAction(action string) {
	o.Action = action
}

// WithTid adds the tid to the update consent action params
func (o *UpdateConsentActionParams) WithTid(tid string) *UpdateConsentActionParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the update consent action params
func (o *UpdateConsentActionParams) SetTid(tid string) {
	o.Tid = tid
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateConsentActionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ConsentAction != nil {
		if err := r.SetBodyParam(o.ConsentAction); err != nil {
			return err
		}
	}

	// path param action
	if err := r.SetPathParam("action", o.Action); err != nil {
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
