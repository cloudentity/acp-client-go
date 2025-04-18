// Code generated by go-swagger; DO NOT EDIT.

package o_b_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// OpenbankingInternationalStandingOrderConsentIntrospectReader is a Reader for the OpenbankingInternationalStandingOrderConsentIntrospect structure.
type OpenbankingInternationalStandingOrderConsentIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OpenbankingInternationalStandingOrderConsentIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOpenbankingInternationalStandingOrderConsentIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewOpenbankingInternationalStandingOrderConsentIntrospectUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewOpenbankingInternationalStandingOrderConsentIntrospectNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewOpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect] openbankingInternationalStandingOrderConsentIntrospect", response, response.Code())
	}
}

// NewOpenbankingInternationalStandingOrderConsentIntrospectOK creates a OpenbankingInternationalStandingOrderConsentIntrospectOK with default headers values
func NewOpenbankingInternationalStandingOrderConsentIntrospectOK() *OpenbankingInternationalStandingOrderConsentIntrospectOK {
	return &OpenbankingInternationalStandingOrderConsentIntrospectOK{}
}

/*
OpenbankingInternationalStandingOrderConsentIntrospectOK describes a response with status code 200, with default header values.

Introspect Openbanking International Standing Order Consent Response
*/
type OpenbankingInternationalStandingOrderConsentIntrospectOK struct {
	Payload *OpenbankingInternationalStandingOrderConsentIntrospectOKBody
}

// IsSuccess returns true when this openbanking international standing order consent introspect o k response has a 2xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this openbanking international standing order consent introspect o k response has a 3xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking international standing order consent introspect o k response has a 4xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this openbanking international standing order consent introspect o k response has a 5xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking international standing order consent introspect o k response a status code equal to that given
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the openbanking international standing order consent introspect o k response
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) Code() int {
	return 200
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectOK %s", 200, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectOK %s", 200, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) GetPayload() *OpenbankingInternationalStandingOrderConsentIntrospectOKBody {
	return o.Payload
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(OpenbankingInternationalStandingOrderConsentIntrospectOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingInternationalStandingOrderConsentIntrospectUnauthorized creates a OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized with default headers values
func NewOpenbankingInternationalStandingOrderConsentIntrospectUnauthorized() *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized {
	return &OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized{}
}

/*
OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking international standing order consent introspect unauthorized response has a 2xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking international standing order consent introspect unauthorized response has a 3xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking international standing order consent introspect unauthorized response has a 4xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking international standing order consent introspect unauthorized response has a 5xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking international standing order consent introspect unauthorized response a status code equal to that given
func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the openbanking international standing order consent introspect unauthorized response
func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) Code() int {
	return 401
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectUnauthorized %s", 401, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectUnauthorized %s", 401, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingInternationalStandingOrderConsentIntrospectNotFound creates a OpenbankingInternationalStandingOrderConsentIntrospectNotFound with default headers values
func NewOpenbankingInternationalStandingOrderConsentIntrospectNotFound() *OpenbankingInternationalStandingOrderConsentIntrospectNotFound {
	return &OpenbankingInternationalStandingOrderConsentIntrospectNotFound{}
}

/*
OpenbankingInternationalStandingOrderConsentIntrospectNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type OpenbankingInternationalStandingOrderConsentIntrospectNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking international standing order consent introspect not found response has a 2xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking international standing order consent introspect not found response has a 3xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking international standing order consent introspect not found response has a 4xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking international standing order consent introspect not found response has a 5xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking international standing order consent introspect not found response a status code equal to that given
func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the openbanking international standing order consent introspect not found response
func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) Code() int {
	return 404
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectNotFound %s", 404, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectNotFound %s", 404, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests creates a OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests with default headers values
func NewOpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests() *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests {
	return &OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests{}
}

/*
OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking international standing order consent introspect too many requests response has a 2xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking international standing order consent introspect too many requests response has a 3xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking international standing order consent introspect too many requests response has a 4xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking international standing order consent introspect too many requests response has a 5xx status code
func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking international standing order consent introspect too many requests response a status code equal to that given
func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the openbanking international standing order consent introspect too many requests response
func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) Code() int {
	return 429
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectTooManyRequests %s", 429, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/international-standing-order-consents/introspect][%d] openbankingInternationalStandingOrderConsentIntrospectTooManyRequests %s", 429, payload)
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingInternationalStandingOrderConsentIntrospectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
OpenbankingInternationalStandingOrderConsentIntrospectOKBody openbanking international standing order consent introspect o k body
swagger:model OpenbankingInternationalStandingOrderConsentIntrospectOKBody
*/
type OpenbankingInternationalStandingOrderConsentIntrospectOKBody struct {
	models.IntrospectResponse

	models.InternationalStandingOrderConsent

	// account i ds
	AccountIDs []string `json:"AccountIDs" yaml:"AccountIDs"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOKBody) UnmarshalJSON(raw []byte) error {
	// OpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO0
	var openbankingInternationalStandingOrderConsentIntrospectOKBodyAO0 models.IntrospectResponse
	if err := swag.ReadJSON(raw, &openbankingInternationalStandingOrderConsentIntrospectOKBodyAO0); err != nil {
		return err
	}
	o.IntrospectResponse = openbankingInternationalStandingOrderConsentIntrospectOKBodyAO0

	// OpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO1
	var openbankingInternationalStandingOrderConsentIntrospectOKBodyAO1 models.InternationalStandingOrderConsent
	if err := swag.ReadJSON(raw, &openbankingInternationalStandingOrderConsentIntrospectOKBodyAO1); err != nil {
		return err
	}
	o.InternationalStandingOrderConsent = openbankingInternationalStandingOrderConsentIntrospectOKBodyAO1

	// OpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2
	var dataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2 struct {
		AccountIDs []string `json:"AccountIDs"`
	}
	if err := swag.ReadJSON(raw, &dataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2); err != nil {
		return err
	}

	o.AccountIDs = dataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2.AccountIDs

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o OpenbankingInternationalStandingOrderConsentIntrospectOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 3)

	openbankingInternationalStandingOrderConsentIntrospectOKBodyAO0, err := swag.WriteJSON(o.IntrospectResponse)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, openbankingInternationalStandingOrderConsentIntrospectOKBodyAO0)

	openbankingInternationalStandingOrderConsentIntrospectOKBodyAO1, err := swag.WriteJSON(o.InternationalStandingOrderConsent)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, openbankingInternationalStandingOrderConsentIntrospectOKBodyAO1)
	var dataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2 struct {
		AccountIDs []string `json:"AccountIDs"`
	}

	dataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2.AccountIDs = o.AccountIDs

	jsonDataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2, errOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2 := swag.WriteJSON(dataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2)
	if errOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2 != nil {
		return nil, errOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2
	}
	_parts = append(_parts, jsonDataOpenbankingInternationalStandingOrderConsentIntrospectOKBodyAO2)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this openbanking international standing order consent introspect o k body
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.Validate(formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with models.InternationalStandingOrderConsent
	if err := o.InternationalStandingOrderConsent.Validate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validate this openbanking international standing order consent introspect o k body based on the context it is used
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with models.InternationalStandingOrderConsent
	if err := o.InternationalStandingOrderConsent.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *OpenbankingInternationalStandingOrderConsentIntrospectOKBody) UnmarshalBinary(b []byte) error {
	var res OpenbankingInternationalStandingOrderConsentIntrospectOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}
