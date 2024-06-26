// Code generated by go-swagger; DO NOT EDIT.

package b2_b_users

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

	"github.com/cloudentity/acp-client-go/clients/identity/models"
)

// NewUpdateB2BUserParams creates a new UpdateB2BUserParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateB2BUserParams() *UpdateB2BUserParams {
	return &UpdateB2BUserParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateB2BUserParamsWithTimeout creates a new UpdateB2BUserParams object
// with the ability to set a timeout on a request.
func NewUpdateB2BUserParamsWithTimeout(timeout time.Duration) *UpdateB2BUserParams {
	return &UpdateB2BUserParams{
		timeout: timeout,
	}
}

// NewUpdateB2BUserParamsWithContext creates a new UpdateB2BUserParams object
// with the ability to set a context for a request.
func NewUpdateB2BUserParamsWithContext(ctx context.Context) *UpdateB2BUserParams {
	return &UpdateB2BUserParams{
		Context: ctx,
	}
}

// NewUpdateB2BUserParamsWithHTTPClient creates a new UpdateB2BUserParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateB2BUserParamsWithHTTPClient(client *http.Client) *UpdateB2BUserParams {
	return &UpdateB2BUserParams{
		HTTPClient: client,
	}
}

/*
UpdateB2BUserParams contains all the parameters to send to the API endpoint

	for the update b2 b user operation.

	Typically these are written to a http.Request.
*/
type UpdateB2BUserParams struct {

	// UpdateUser.
	UpdateUser *models.BaseUpdateUser

	// IPID.
	IPID string

	// UserID.
	UserID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update b2 b user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateB2BUserParams) WithDefaults() *UpdateB2BUserParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update b2 b user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateB2BUserParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update b2 b user params
func (o *UpdateB2BUserParams) WithTimeout(timeout time.Duration) *UpdateB2BUserParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update b2 b user params
func (o *UpdateB2BUserParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update b2 b user params
func (o *UpdateB2BUserParams) WithContext(ctx context.Context) *UpdateB2BUserParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update b2 b user params
func (o *UpdateB2BUserParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update b2 b user params
func (o *UpdateB2BUserParams) WithHTTPClient(client *http.Client) *UpdateB2BUserParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update b2 b user params
func (o *UpdateB2BUserParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithUpdateUser adds the updateUser to the update b2 b user params
func (o *UpdateB2BUserParams) WithUpdateUser(updateUser *models.BaseUpdateUser) *UpdateB2BUserParams {
	o.SetUpdateUser(updateUser)
	return o
}

// SetUpdateUser adds the updateUser to the update b2 b user params
func (o *UpdateB2BUserParams) SetUpdateUser(updateUser *models.BaseUpdateUser) {
	o.UpdateUser = updateUser
}

// WithIPID adds the iPID to the update b2 b user params
func (o *UpdateB2BUserParams) WithIPID(iPID string) *UpdateB2BUserParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the update b2 b user params
func (o *UpdateB2BUserParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithUserID adds the userID to the update b2 b user params
func (o *UpdateB2BUserParams) WithUserID(userID string) *UpdateB2BUserParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the update b2 b user params
func (o *UpdateB2BUserParams) SetUserID(userID string) {
	o.UserID = userID
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateB2BUserParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.UpdateUser != nil {
		if err := r.SetBodyParam(o.UpdateUser); err != nil {
			return err
		}
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
