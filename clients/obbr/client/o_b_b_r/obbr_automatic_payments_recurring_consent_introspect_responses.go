// Code generated by go-swagger; DO NOT EDIT.

package o_b_b_r

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// ObbrAutomaticPaymentsRecurringConsentIntrospectReader is a Reader for the ObbrAutomaticPaymentsRecurringConsentIntrospect structure.
type ObbrAutomaticPaymentsRecurringConsentIntrospectReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewObbrAutomaticPaymentsRecurringConsentIntrospectOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewObbrAutomaticPaymentsRecurringConsentIntrospectNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect] obbrAutomaticPaymentsRecurringConsentIntrospect", response, response.Code())
	}
}

// NewObbrAutomaticPaymentsRecurringConsentIntrospectOK creates a ObbrAutomaticPaymentsRecurringConsentIntrospectOK with default headers values
func NewObbrAutomaticPaymentsRecurringConsentIntrospectOK() *ObbrAutomaticPaymentsRecurringConsentIntrospectOK {
	return &ObbrAutomaticPaymentsRecurringConsentIntrospectOK{}
}

/*
ObbrAutomaticPaymentsRecurringConsentIntrospectOK describes a response with status code 200, with default header values.

Introspect Openbanking Brazil Data Access Consent Response
*/
type ObbrAutomaticPaymentsRecurringConsentIntrospectOK struct {
	Payload *models.IntrospectOBBRAutomaticPaymentsRecurringConsentResponse
}

// IsSuccess returns true when this obbr automatic payments recurring consent introspect o k response has a 2xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this obbr automatic payments recurring consent introspect o k response has a 3xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr automatic payments recurring consent introspect o k response has a 4xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this obbr automatic payments recurring consent introspect o k response has a 5xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr automatic payments recurring consent introspect o k response a status code equal to that given
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the obbr automatic payments recurring consent introspect o k response
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) Code() int {
	return 200
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectOK  %+v", 200, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) GetPayload() *models.IntrospectOBBRAutomaticPaymentsRecurringConsentResponse {
	return o.Payload
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.IntrospectOBBRAutomaticPaymentsRecurringConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized creates a ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized with default headers values
func NewObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized() *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized {
	return &ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized{}
}

/*
ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized describes a response with status code 401, with default header values.

ErrorResponse
*/
type ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this obbr automatic payments recurring consent introspect unauthorized response has a 2xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this obbr automatic payments recurring consent introspect unauthorized response has a 3xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr automatic payments recurring consent introspect unauthorized response has a 4xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this obbr automatic payments recurring consent introspect unauthorized response has a 5xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr automatic payments recurring consent introspect unauthorized response a status code equal to that given
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the obbr automatic payments recurring consent introspect unauthorized response
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) Code() int {
	return 401
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized  %+v", 401, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObbrAutomaticPaymentsRecurringConsentIntrospectNotFound creates a ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound with default headers values
func NewObbrAutomaticPaymentsRecurringConsentIntrospectNotFound() *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound {
	return &ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound{}
}

/*
ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound describes a response with status code 404, with default header values.

ErrorResponse
*/
type ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this obbr automatic payments recurring consent introspect not found response has a 2xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this obbr automatic payments recurring consent introspect not found response has a 3xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr automatic payments recurring consent introspect not found response has a 4xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this obbr automatic payments recurring consent introspect not found response has a 5xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr automatic payments recurring consent introspect not found response a status code equal to that given
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the obbr automatic payments recurring consent introspect not found response
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) Code() int {
	return 404
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectNotFound  %+v", 404, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests creates a ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests with default headers values
func NewObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests() *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests {
	return &ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests{}
}

/*
ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests describes a response with status code 429, with default header values.

ErrorResponse
*/
type ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this obbr automatic payments recurring consent introspect too many requests response has a 2xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this obbr automatic payments recurring consent introspect too many requests response has a 3xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this obbr automatic payments recurring consent introspect too many requests response has a 4xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this obbr automatic payments recurring consent introspect too many requests response has a 5xx status code
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this obbr automatic payments recurring consent introspect too many requests response a status code equal to that given
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the obbr automatic payments recurring consent introspect too many requests response
func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) Code() int {
	return 429
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking-brasil/open-banking/automatic-payments/v1/recurring-consents/introspect][%d] obbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests  %+v", 429, o.Payload)
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *ObbrAutomaticPaymentsRecurringConsentIntrospectTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
