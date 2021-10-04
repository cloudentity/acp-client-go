// Code generated by go-swagger; DO NOT EDIT.

package openbanking_common

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

// NewGetOBConsentsParams creates a new GetOBConsentsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetOBConsentsParams() *GetOBConsentsParams {
	return &GetOBConsentsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetOBConsentsParamsWithTimeout creates a new GetOBConsentsParams object
// with the ability to set a timeout on a request.
func NewGetOBConsentsParamsWithTimeout(timeout time.Duration) *GetOBConsentsParams {
	return &GetOBConsentsParams{
		timeout: timeout,
	}
}

// NewGetOBConsentsParamsWithContext creates a new GetOBConsentsParams object
// with the ability to set a context for a request.
func NewGetOBConsentsParamsWithContext(ctx context.Context) *GetOBConsentsParams {
	return &GetOBConsentsParams{
		Context: ctx,
	}
}

// NewGetOBConsentsParamsWithHTTPClient creates a new GetOBConsentsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetOBConsentsParamsWithHTTPClient(client *http.Client) *GetOBConsentsParams {
	return &GetOBConsentsParams{
		HTTPClient: client,
	}
}

/* GetOBConsentsParams contains all the parameters to send to the API endpoint
   for the get o b consents operation.

   Typically these are written to a http.Request.
*/
type GetOBConsentsParams struct {

	/* Accounts.

	     Optional list of accounts
	Accounts
	*/
	Accounts []string

	/* AfterConsentID.

	     optional list consents after given id
	AfterConsentID
	*/
	AfterConsentID *string

	/* Aid.

	   Authorization server id

	   Default: "default"
	*/
	Aid string

	/* BeforeConsentID.

	     optional list consents before given id
	BeforeConsentID
	*/
	BeforeConsentID *string

	/* ClientID.

	     Optional client id
	ClientID
	*/
	ClientID *string

	/* Limit.

	     optional limit results
	Limit

	     Format: int64
	     Default: 20
	*/
	Limit *int64

	/* Order.

	     optional sort consents by given fields
	Order
	*/
	Order *string

	/* Sort.

	     optional sort consents by given fields
	Sort
	*/
	Sort *string

	/* Status.

	     Optional status
	Status
	*/
	Status []string

	// Tid.
	//
	// Default: "default"
	Tid string

	/* Types.

	     Optional type
	Types
	*/
	Types []string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get o b consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOBConsentsParams) WithDefaults() *GetOBConsentsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get o b consents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetOBConsentsParams) SetDefaults() {
	var (
		aidDefault = string("default")

		limitDefault = int64(20)

		tidDefault = string("default")
	)

	val := GetOBConsentsParams{
		Aid:   aidDefault,
		Limit: &limitDefault,
		Tid:   tidDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get o b consents params
func (o *GetOBConsentsParams) WithTimeout(timeout time.Duration) *GetOBConsentsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get o b consents params
func (o *GetOBConsentsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get o b consents params
func (o *GetOBConsentsParams) WithContext(ctx context.Context) *GetOBConsentsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get o b consents params
func (o *GetOBConsentsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get o b consents params
func (o *GetOBConsentsParams) WithHTTPClient(client *http.Client) *GetOBConsentsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get o b consents params
func (o *GetOBConsentsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAccounts adds the accounts to the get o b consents params
func (o *GetOBConsentsParams) WithAccounts(accounts []string) *GetOBConsentsParams {
	o.SetAccounts(accounts)
	return o
}

// SetAccounts adds the accounts to the get o b consents params
func (o *GetOBConsentsParams) SetAccounts(accounts []string) {
	o.Accounts = accounts
}

// WithAfterConsentID adds the afterConsentID to the get o b consents params
func (o *GetOBConsentsParams) WithAfterConsentID(afterConsentID *string) *GetOBConsentsParams {
	o.SetAfterConsentID(afterConsentID)
	return o
}

// SetAfterConsentID adds the afterConsentId to the get o b consents params
func (o *GetOBConsentsParams) SetAfterConsentID(afterConsentID *string) {
	o.AfterConsentID = afterConsentID
}

// WithAid adds the aid to the get o b consents params
func (o *GetOBConsentsParams) WithAid(aid string) *GetOBConsentsParams {
	o.SetAid(aid)
	return o
}

// SetAid adds the aid to the get o b consents params
func (o *GetOBConsentsParams) SetAid(aid string) {
	o.Aid = aid
}

// WithBeforeConsentID adds the beforeConsentID to the get o b consents params
func (o *GetOBConsentsParams) WithBeforeConsentID(beforeConsentID *string) *GetOBConsentsParams {
	o.SetBeforeConsentID(beforeConsentID)
	return o
}

// SetBeforeConsentID adds the beforeConsentId to the get o b consents params
func (o *GetOBConsentsParams) SetBeforeConsentID(beforeConsentID *string) {
	o.BeforeConsentID = beforeConsentID
}

// WithClientID adds the clientID to the get o b consents params
func (o *GetOBConsentsParams) WithClientID(clientID *string) *GetOBConsentsParams {
	o.SetClientID(clientID)
	return o
}

// SetClientID adds the clientId to the get o b consents params
func (o *GetOBConsentsParams) SetClientID(clientID *string) {
	o.ClientID = clientID
}

// WithLimit adds the limit to the get o b consents params
func (o *GetOBConsentsParams) WithLimit(limit *int64) *GetOBConsentsParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the get o b consents params
func (o *GetOBConsentsParams) SetLimit(limit *int64) {
	o.Limit = limit
}

// WithOrder adds the order to the get o b consents params
func (o *GetOBConsentsParams) WithOrder(order *string) *GetOBConsentsParams {
	o.SetOrder(order)
	return o
}

// SetOrder adds the order to the get o b consents params
func (o *GetOBConsentsParams) SetOrder(order *string) {
	o.Order = order
}

// WithSort adds the sort to the get o b consents params
func (o *GetOBConsentsParams) WithSort(sort *string) *GetOBConsentsParams {
	o.SetSort(sort)
	return o
}

// SetSort adds the sort to the get o b consents params
func (o *GetOBConsentsParams) SetSort(sort *string) {
	o.Sort = sort
}

// WithStatus adds the status to the get o b consents params
func (o *GetOBConsentsParams) WithStatus(status []string) *GetOBConsentsParams {
	o.SetStatus(status)
	return o
}

// SetStatus adds the status to the get o b consents params
func (o *GetOBConsentsParams) SetStatus(status []string) {
	o.Status = status
}

// WithTid adds the tid to the get o b consents params
func (o *GetOBConsentsParams) WithTid(tid string) *GetOBConsentsParams {
	o.SetTid(tid)
	return o
}

// SetTid adds the tid to the get o b consents params
func (o *GetOBConsentsParams) SetTid(tid string) {
	o.Tid = tid
}

// WithTypes adds the types to the get o b consents params
func (o *GetOBConsentsParams) WithTypes(types []string) *GetOBConsentsParams {
	o.SetTypes(types)
	return o
}

// SetTypes adds the types to the get o b consents params
func (o *GetOBConsentsParams) SetTypes(types []string) {
	o.Types = types
}

// WriteToRequest writes these params to a swagger request
func (o *GetOBConsentsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Accounts != nil {

		// binding items for accounts
		joinedAccounts := o.bindParamAccounts(reg)

		// query array param accounts
		if err := r.SetQueryParam("accounts", joinedAccounts...); err != nil {
			return err
		}
	}

	if o.AfterConsentID != nil {

		// query param after_consent_id
		var qrAfterConsentID string

		if o.AfterConsentID != nil {
			qrAfterConsentID = *o.AfterConsentID
		}
		qAfterConsentID := qrAfterConsentID
		if qAfterConsentID != "" {

			if err := r.SetQueryParam("after_consent_id", qAfterConsentID); err != nil {
				return err
			}
		}
	}

	// path param aid
	if err := r.SetPathParam("aid", o.Aid); err != nil {
		return err
	}

	if o.BeforeConsentID != nil {

		// query param before_consent_id
		var qrBeforeConsentID string

		if o.BeforeConsentID != nil {
			qrBeforeConsentID = *o.BeforeConsentID
		}
		qBeforeConsentID := qrBeforeConsentID
		if qBeforeConsentID != "" {

			if err := r.SetQueryParam("before_consent_id", qBeforeConsentID); err != nil {
				return err
			}
		}
	}

	if o.ClientID != nil {

		// query param client_id
		var qrClientID string

		if o.ClientID != nil {
			qrClientID = *o.ClientID
		}
		qClientID := qrClientID
		if qClientID != "" {

			if err := r.SetQueryParam("client_id", qClientID); err != nil {
				return err
			}
		}
	}

	if o.Limit != nil {

		// query param limit
		var qrLimit int64

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt64(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.Order != nil {

		// query param order
		var qrOrder string

		if o.Order != nil {
			qrOrder = *o.Order
		}
		qOrder := qrOrder
		if qOrder != "" {

			if err := r.SetQueryParam("order", qOrder); err != nil {
				return err
			}
		}
	}

	if o.Sort != nil {

		// query param sort
		var qrSort string

		if o.Sort != nil {
			qrSort = *o.Sort
		}
		qSort := qrSort
		if qSort != "" {

			if err := r.SetQueryParam("sort", qSort); err != nil {
				return err
			}
		}
	}

	if o.Status != nil {

		// binding items for status
		joinedStatus := o.bindParamStatus(reg)

		// query array param status
		if err := r.SetQueryParam("status", joinedStatus...); err != nil {
			return err
		}
	}

	// path param tid
	if err := r.SetPathParam("tid", o.Tid); err != nil {
		return err
	}

	if o.Types != nil {

		// binding items for types
		joinedTypes := o.bindParamTypes(reg)

		// query array param types
		if err := r.SetQueryParam("types", joinedTypes...); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindParamGetOBConsents binds the parameter accounts
func (o *GetOBConsentsParams) bindParamAccounts(formats strfmt.Registry) []string {
	accountsIR := o.Accounts

	var accountsIC []string
	for _, accountsIIR := range accountsIR { // explode []string

		accountsIIV := accountsIIR // string as string
		accountsIC = append(accountsIC, accountsIIV)
	}

	// items.CollectionFormat: ""
	accountsIS := swag.JoinByFormat(accountsIC, "")

	return accountsIS
}

// bindParamGetOBConsents binds the parameter status
func (o *GetOBConsentsParams) bindParamStatus(formats strfmt.Registry) []string {
	statusIR := o.Status

	var statusIC []string
	for _, statusIIR := range statusIR { // explode []string

		statusIIV := statusIIR // string as string
		statusIC = append(statusIC, statusIIV)
	}

	// items.CollectionFormat: ""
	statusIS := swag.JoinByFormat(statusIC, "")

	return statusIS
}

// bindParamGetOBConsents binds the parameter types
func (o *GetOBConsentsParams) bindParamTypes(formats strfmt.Registry) []string {
	typesIR := o.Types

	var typesIC []string
	for _, typesIIR := range typesIR { // explode []string

		typesIIV := typesIIR // string as string
		typesIC = append(typesIC, typesIIV)
	}

	// items.CollectionFormat: ""
	typesIS := swag.JoinByFormat(typesIC, "")

	return typesIS
}
