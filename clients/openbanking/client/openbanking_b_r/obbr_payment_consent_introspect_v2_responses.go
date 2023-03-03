// Code generated by go-swagger; DO NOT EDIT.

package openbanking_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// ObbrPaymentConsentIntrospectV2Reader is a Reader for the ObbrPaymentConsentIntrospectV2 structure.
type ObbrPaymentConsentIntrospectV2Reader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ObbrPaymentConsentIntrospectV2Reader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewObbrPaymentConsentIntrospectV2OK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewObbrPaymentConsentIntrospectV2Unauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewObbrPaymentConsentIntrospectV2NotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewObbrPaymentConsentIntrospectV2TooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewObbrPaymentConsentIntrospectV2OK creates a ObbrPaymentConsentIntrospectV2OK with default headers values
func NewObbrPaymentConsentIntrospectV2OK() *ObbrPaymentConsentIntrospectV2OK {
	return &ObbrPaymentConsentIntrospectV2OK{}
}

/*
ObbrPaymentConsentIntrospectV2OK describes a response with status code 200, with default header values.

Introspect Openbanking Brazil Payment Consent V2 Response
*/
type ObbrPaymentConsentIntrospectV2OK struct {
	Payload *models.IntrospectOBBRPaymentConsentResponseV2
}

// IsSuccess returns true when this obbr payment consent introspect v2 o k response has a 2xx status code
func (o *ObbrPaymentConsentIntrospectV2OK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this obbr payment consent introspect v2 o k response has a 3xx status code
func (o *ObbrPaymentConsentIntrospectV2OK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr payment consent introspect v2 o k response has a 4xx status code
func (o *ObbrPaymentConsentIntrospectV2OK) IsClientError() bool {
	return false
}

// IsServerError returns true when this obbr payment consent introspect v2 o k response has a 5xx status code
func (o *ObbrPaymentConsentIntrospectV2OK) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr payment consent introspect v2 o k response a status code equal to that given
func (o *ObbrPaymentConsentIntrospectV2OK) IsCode(code int) bool {
	return code == 200
}

func (o *ObbrPaymentConsentIntrospectV2OK) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2OK  %+v", 200, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2OK) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2OK  %+v", 200, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2OK) GetPayload() *models.IntrospectOBBRPaymentConsentResponseV2 {
	return o.Payload
}

func (o *ObbrPaymentConsentIntrospectV2OK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.IntrospectOBBRPaymentConsentResponseV2)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObbrPaymentConsentIntrospectV2Unauthorized creates a ObbrPaymentConsentIntrospectV2Unauthorized with default headers values
func NewObbrPaymentConsentIntrospectV2Unauthorized() *ObbrPaymentConsentIntrospectV2Unauthorized {
	return &ObbrPaymentConsentIntrospectV2Unauthorized{}
}

/*
ObbrPaymentConsentIntrospectV2Unauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type ObbrPaymentConsentIntrospectV2Unauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this obbr payment consent introspect v2 unauthorized response has a 2xx status code
func (o *ObbrPaymentConsentIntrospectV2Unauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this obbr payment consent introspect v2 unauthorized response has a 3xx status code
func (o *ObbrPaymentConsentIntrospectV2Unauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr payment consent introspect v2 unauthorized response has a 4xx status code
func (o *ObbrPaymentConsentIntrospectV2Unauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this obbr payment consent introspect v2 unauthorized response has a 5xx status code
func (o *ObbrPaymentConsentIntrospectV2Unauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr payment consent introspect v2 unauthorized response a status code equal to that given
func (o *ObbrPaymentConsentIntrospectV2Unauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *ObbrPaymentConsentIntrospectV2Unauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2Unauthorized  %+v", 401, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2Unauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2Unauthorized  %+v", 401, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2Unauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *ObbrPaymentConsentIntrospectV2Unauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObbrPaymentConsentIntrospectV2NotFound creates a ObbrPaymentConsentIntrospectV2NotFound with default headers values
func NewObbrPaymentConsentIntrospectV2NotFound() *ObbrPaymentConsentIntrospectV2NotFound {
	return &ObbrPaymentConsentIntrospectV2NotFound{}
}

/*
ObbrPaymentConsentIntrospectV2NotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type ObbrPaymentConsentIntrospectV2NotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this obbr payment consent introspect v2 not found response has a 2xx status code
func (o *ObbrPaymentConsentIntrospectV2NotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this obbr payment consent introspect v2 not found response has a 3xx status code
func (o *ObbrPaymentConsentIntrospectV2NotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr payment consent introspect v2 not found response has a 4xx status code
func (o *ObbrPaymentConsentIntrospectV2NotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this obbr payment consent introspect v2 not found response has a 5xx status code
func (o *ObbrPaymentConsentIntrospectV2NotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr payment consent introspect v2 not found response a status code equal to that given
func (o *ObbrPaymentConsentIntrospectV2NotFound) IsCode(code int) bool {
	return code == 404
}

func (o *ObbrPaymentConsentIntrospectV2NotFound) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2NotFound  %+v", 404, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2NotFound) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2NotFound  %+v", 404, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2NotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *ObbrPaymentConsentIntrospectV2NotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObbrPaymentConsentIntrospectV2TooManyRequests creates a ObbrPaymentConsentIntrospectV2TooManyRequests with default headers values
func NewObbrPaymentConsentIntrospectV2TooManyRequests() *ObbrPaymentConsentIntrospectV2TooManyRequests {
	return &ObbrPaymentConsentIntrospectV2TooManyRequests{}
}

/*
ObbrPaymentConsentIntrospectV2TooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type ObbrPaymentConsentIntrospectV2TooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this obbr payment consent introspect v2 too many requests response has a 2xx status code
func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this obbr payment consent introspect v2 too many requests response has a 3xx status code
func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr payment consent introspect v2 too many requests response has a 4xx status code
func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this obbr payment consent introspect v2 too many requests response has a 5xx status code
func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr payment consent introspect v2 too many requests response a status code equal to that given
func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/payments/v2/consents/introspect][%d] obbrPaymentConsentIntrospectV2TooManyRequests  %+v", 429, o.Payload)
}

func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *ObbrPaymentConsentIntrospectV2TooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
