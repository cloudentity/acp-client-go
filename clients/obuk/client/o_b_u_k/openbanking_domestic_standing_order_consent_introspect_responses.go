// Code generated by go-swagger; DO NOT EDIT.

package o_b_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"fmt"
	"io"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// OpenbankingDomesticStandingOrderConsentIntrospectReader is a Reader for the OpenbankingDomesticStandingOrderConsentIntrospect structure.
type OpenbankingDomesticStandingOrderConsentIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OpenbankingDomesticStandingOrderConsentIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOpenbankingDomesticStandingOrderConsentIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewOpenbankingDomesticStandingOrderConsentIntrospectUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewOpenbankingDomesticStandingOrderConsentIntrospectNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewOpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewOpenbankingDomesticStandingOrderConsentIntrospectOK creates a OpenbankingDomesticStandingOrderConsentIntrospectOK with default headers values
func NewOpenbankingDomesticStandingOrderConsentIntrospectOK() *OpenbankingDomesticStandingOrderConsentIntrospectOK {
	return &OpenbankingDomesticStandingOrderConsentIntrospectOK{}
}

/*
OpenbankingDomesticStandingOrderConsentIntrospectOK describes a response with status code 200, with default header values.

Introspect Openbanking Domestic Standing Order Consent Response
*/
type OpenbankingDomesticStandingOrderConsentIntrospectOK struct {
	Payload *OpenbankingDomesticStandingOrderConsentIntrospectOKBody
}

// IsSuccess returns true when this openbanking domestic standing order consent introspect o k response has a 2xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this openbanking domestic standing order consent introspect o k response has a 3xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking domestic standing order consent introspect o k response has a 4xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this openbanking domestic standing order consent introspect o k response has a 5xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking domestic standing order consent introspect o k response a status code equal to that given
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the openbanking domestic standing order consent introspect o k response
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) Code() int {
	return 200
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) GetPayload() *OpenbankingDomesticStandingOrderConsentIntrospectOKBody {
	return o.Payload
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(OpenbankingDomesticStandingOrderConsentIntrospectOKBody)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingDomesticStandingOrderConsentIntrospectUnauthorized creates a OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized with default headers values
func NewOpenbankingDomesticStandingOrderConsentIntrospectUnauthorized() *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized {
	return &OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized{}
}

/*
OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking domestic standing order consent introspect unauthorized response has a 2xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking domestic standing order consent introspect unauthorized response has a 3xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking domestic standing order consent introspect unauthorized response has a 4xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking domestic standing order consent introspect unauthorized response has a 5xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking domestic standing order consent introspect unauthorized response a status code equal to that given
func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the openbanking domestic standing order consent introspect unauthorized response
func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) Code() int {
	return 401
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingDomesticStandingOrderConsentIntrospectNotFound creates a OpenbankingDomesticStandingOrderConsentIntrospectNotFound with default headers values
func NewOpenbankingDomesticStandingOrderConsentIntrospectNotFound() *OpenbankingDomesticStandingOrderConsentIntrospectNotFound {
	return &OpenbankingDomesticStandingOrderConsentIntrospectNotFound{}
}

/*
OpenbankingDomesticStandingOrderConsentIntrospectNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type OpenbankingDomesticStandingOrderConsentIntrospectNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking domestic standing order consent introspect not found response has a 2xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking domestic standing order consent introspect not found response has a 3xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking domestic standing order consent introspect not found response has a 4xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking domestic standing order consent introspect not found response has a 5xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking domestic standing order consent introspect not found response a status code equal to that given
func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the openbanking domestic standing order consent introspect not found response
func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) Code() int {
	return 404
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewOpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests creates a OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests with default headers values
func NewOpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests() *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests {
	return &OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests{}
}

/*
OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this openbanking domestic standing order consent introspect too many requests response has a 2xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this openbanking domestic standing order consent introspect too many requests response has a 3xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this openbanking domestic standing order consent introspect too many requests response has a 4xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this openbanking domestic standing order consent introspect too many requests response has a 5xx status code
func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this openbanking domestic standing order consent introspect too many requests response a status code equal to that given
func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the openbanking domestic standing order consent introspect too many requests response
func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) Code() int {
	return 429
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking/v3.1/pisp/domestic-standing-order-consents/introspect][%d] openbankingDomesticStandingOrderConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *OpenbankingDomesticStandingOrderConsentIntrospectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

/*
OpenbankingDomesticStandingOrderConsentIntrospectOKBody openbanking domestic standing order consent introspect o k body
swagger:model OpenbankingDomesticStandingOrderConsentIntrospectOKBody
*/
type OpenbankingDomesticStandingOrderConsentIntrospectOKBody struct {
	models.IntrospectResponse

	models.DomesticStandingOrderConsent

	// account i ds
	AccountIDs []string `json:"AccountIDs"`
}

// UnmarshalJSON unmarshals this object from a JSON structure
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOKBody) UnmarshalJSON(raw []byte) error {
	// OpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO0
	var openbankingDomesticStandingOrderConsentIntrospectOKBodyAO0 models.IntrospectResponse
	if err := swag.ReadJSON(raw, &openbankingDomesticStandingOrderConsentIntrospectOKBodyAO0); err != nil {
		return err
	}
	o.IntrospectResponse = openbankingDomesticStandingOrderConsentIntrospectOKBodyAO0

	// OpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO1
	var openbankingDomesticStandingOrderConsentIntrospectOKBodyAO1 models.DomesticStandingOrderConsent
	if err := swag.ReadJSON(raw, &openbankingDomesticStandingOrderConsentIntrospectOKBodyAO1); err != nil {
		return err
	}
	o.DomesticStandingOrderConsent = openbankingDomesticStandingOrderConsentIntrospectOKBodyAO1

	// OpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2
	var dataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2 struct {
		AccountIDs []string `json:"AccountIDs"`
	}
	if err := swag.ReadJSON(raw, &dataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2); err != nil {
		return err
	}

	o.AccountIDs = dataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2.AccountIDs

	return nil
}

// MarshalJSON marshals this object to a JSON structure
func (o OpenbankingDomesticStandingOrderConsentIntrospectOKBody) MarshalJSON() ([]byte, error) {
	_parts := make([][]byte, 0, 3)

	openbankingDomesticStandingOrderConsentIntrospectOKBodyAO0, err := swag.WriteJSON(o.IntrospectResponse)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, openbankingDomesticStandingOrderConsentIntrospectOKBodyAO0)

	openbankingDomesticStandingOrderConsentIntrospectOKBodyAO1, err := swag.WriteJSON(o.DomesticStandingOrderConsent)
	if err != nil {
		return nil, err
	}
	_parts = append(_parts, openbankingDomesticStandingOrderConsentIntrospectOKBodyAO1)
	var dataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2 struct {
		AccountIDs []string `json:"AccountIDs"`
	}

	dataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2.AccountIDs = o.AccountIDs

	jsonDataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2, errOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2 := swag.WriteJSON(dataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2)
	if errOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2 != nil {
		return nil, errOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2
	}
	_parts = append(_parts, jsonDataOpenbankingDomesticStandingOrderConsentIntrospectOKBodyAO2)
	return swag.ConcatJSON(_parts...), nil
}

// Validate validates this openbanking domestic standing order consent introspect o k body
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOKBody) Validate(formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.Validate(formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with models.DomesticStandingOrderConsent
	if err := o.DomesticStandingOrderConsent.Validate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validate this openbanking domestic standing order consent introspect o k body based on the context it is used
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOKBody) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	// validation for a type composition with models.IntrospectResponse
	if err := o.IntrospectResponse.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}
	// validation for a type composition with models.DomesticStandingOrderConsent
	if err := o.DomesticStandingOrderConsent.ContextValidate(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// MarshalBinary interface implementation
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOKBody) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, nil
	}
	return swag.WriteJSON(o)
}

// UnmarshalBinary interface implementation
func (o *OpenbankingDomesticStandingOrderConsentIntrospectOKBody) UnmarshalBinary(b []byte) error {
	var res OpenbankingDomesticStandingOrderConsentIntrospectOKBody
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*o = res
	return nil
}