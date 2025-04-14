// Code generated by go-swagger; DO NOT EDIT.

package groups

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
	"github.com/go-openapi/swag"
)

// NewIsUserInGroupParams creates a new IsUserInGroupParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIsUserInGroupParams() *IsUserInGroupParams {
	return &IsUserInGroupParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewIsUserInGroupParamsWithTimeout creates a new IsUserInGroupParams object
// with the ability to set a timeout on a request.
func NewIsUserInGroupParamsWithTimeout(timeout time.Duration) *IsUserInGroupParams {
	return &IsUserInGroupParams{
		timeout: timeout,
	}
}

// NewIsUserInGroupParamsWithContext creates a new IsUserInGroupParams object
// with the ability to set a context for a request.
func NewIsUserInGroupParamsWithContext(ctx context.Context) *IsUserInGroupParams {
	return &IsUserInGroupParams{
		Context: ctx,
	}
}

// NewIsUserInGroupParamsWithHTTPClient creates a new IsUserInGroupParams object
// with the ability to set a custom HTTPClient for a request.
func NewIsUserInGroupParamsWithHTTPClient(client *http.Client) *IsUserInGroupParams {
	return &IsUserInGroupParams{
		HTTPClient: client,
	}
}

/*
IsUserInGroupParams contains all the parameters to send to the API endpoint

	for the is user in group operation.

	Typically these are written to a http.Request.
*/
type IsUserInGroupParams struct {

	// GroupID.
	GroupID string

	// IPID.
	IPID string

	// UserID.
	UserID string

	// WithNestedGroups.
	WithNestedGroups *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the is user in group params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IsUserInGroupParams) WithDefaults() *IsUserInGroupParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the is user in group params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IsUserInGroupParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the is user in group params
func (o *IsUserInGroupParams) WithTimeout(timeout time.Duration) *IsUserInGroupParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the is user in group params
func (o *IsUserInGroupParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the is user in group params
func (o *IsUserInGroupParams) WithContext(ctx context.Context) *IsUserInGroupParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the is user in group params
func (o *IsUserInGroupParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the is user in group params
func (o *IsUserInGroupParams) WithHTTPClient(client *http.Client) *IsUserInGroupParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the is user in group params
func (o *IsUserInGroupParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGroupID adds the groupID to the is user in group params
func (o *IsUserInGroupParams) WithGroupID(groupID string) *IsUserInGroupParams {
	o.SetGroupID(groupID)
	return o
}

// SetGroupID adds the groupId to the is user in group params
func (o *IsUserInGroupParams) SetGroupID(groupID string) {
	o.GroupID = groupID
}

// WithIPID adds the iPID to the is user in group params
func (o *IsUserInGroupParams) WithIPID(iPID string) *IsUserInGroupParams {
	o.SetIPID(iPID)
	return o
}

// SetIPID adds the ipId to the is user in group params
func (o *IsUserInGroupParams) SetIPID(iPID string) {
	o.IPID = iPID
}

// WithUserID adds the userID to the is user in group params
func (o *IsUserInGroupParams) WithUserID(userID string) *IsUserInGroupParams {
	o.SetUserID(userID)
	return o
}

// SetUserID adds the userId to the is user in group params
func (o *IsUserInGroupParams) SetUserID(userID string) {
	o.UserID = userID
}

// WithWithNestedGroups adds the withNestedGroups to the is user in group params
func (o *IsUserInGroupParams) WithWithNestedGroups(withNestedGroups *bool) *IsUserInGroupParams {
	o.SetWithNestedGroups(withNestedGroups)
	return o
}

// SetWithNestedGroups adds the withNestedGroups to the is user in group params
func (o *IsUserInGroupParams) SetWithNestedGroups(withNestedGroups *bool) {
	o.WithNestedGroups = withNestedGroups
}

// WriteToRequest writes these params to a swagger request
func (o *IsUserInGroupParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param groupID
	if err := r.SetPathParam("groupID", o.GroupID); err != nil {
		return err
	}

	// path param ipID
	if err := r.SetPathParam("ipID", o.IPID); err != nil {
		return err
	}

	// path param userID
	if err := r.SetPathParam("userID", o.UserID); err != nil {
		return err
	}

	if o.WithNestedGroups != nil {

		// query param with_nested_groups
		var qrWithNestedGroups bool

		if o.WithNestedGroups != nil {
			qrWithNestedGroups = *o.WithNestedGroups
		}
		qWithNestedGroups := swag.FormatBool(qrWithNestedGroups)
		if qWithNestedGroups != "" {

			if err := r.SetQueryParam("with_nested_groups", qWithNestedGroups); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
