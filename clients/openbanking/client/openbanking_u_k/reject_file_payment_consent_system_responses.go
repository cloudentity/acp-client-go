// Code generated by go-swagger; DO NOT EDIT.

package openbanking_u_k

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/openbanking/models"
)

// RejectFilePaymentConsentSystemReader is a Reader for the RejectFilePaymentConsentSystem structure.
type RejectFilePaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectFilePaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectFilePaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectFilePaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectFilePaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectFilePaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectFilePaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewRejectFilePaymentConsentSystemOK creates a RejectFilePaymentConsentSystemOK with default headers values
func NewRejectFilePaymentConsentSystemOK() *RejectFilePaymentConsentSystemOK {
	return &RejectFilePaymentConsentSystemOK{}
}

/*
RejectFilePaymentConsentSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectFilePaymentConsentSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject file payment consent system o k response has a 2xx status code
func (o *RejectFilePaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject file payment consent system o k response has a 3xx status code
func (o *RejectFilePaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject file payment consent system o k response has a 4xx status code
func (o *RejectFilePaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject file payment consent system o k response has a 5xx status code
func (o *RejectFilePaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject file payment consent system o k response a status code equal to that given
func (o *RejectFilePaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

func (o *RejectFilePaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectFilePaymentConsentSystemOK) String() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectFilePaymentConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectFilePaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFilePaymentConsentSystemUnauthorized creates a RejectFilePaymentConsentSystemUnauthorized with default headers values
func NewRejectFilePaymentConsentSystemUnauthorized() *RejectFilePaymentConsentSystemUnauthorized {
	return &RejectFilePaymentConsentSystemUnauthorized{}
}

/*
RejectFilePaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

HttpError
*/
type RejectFilePaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject file payment consent system unauthorized response has a 2xx status code
func (o *RejectFilePaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject file payment consent system unauthorized response has a 3xx status code
func (o *RejectFilePaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject file payment consent system unauthorized response has a 4xx status code
func (o *RejectFilePaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject file payment consent system unauthorized response has a 5xx status code
func (o *RejectFilePaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject file payment consent system unauthorized response a status code equal to that given
func (o *RejectFilePaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

func (o *RejectFilePaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectFilePaymentConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectFilePaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFilePaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFilePaymentConsentSystemForbidden creates a RejectFilePaymentConsentSystemForbidden with default headers values
func NewRejectFilePaymentConsentSystemForbidden() *RejectFilePaymentConsentSystemForbidden {
	return &RejectFilePaymentConsentSystemForbidden{}
}

/*
RejectFilePaymentConsentSystemForbidden describes a response with status code 403, with default header values.

HttpError
*/
type RejectFilePaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject file payment consent system forbidden response has a 2xx status code
func (o *RejectFilePaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject file payment consent system forbidden response has a 3xx status code
func (o *RejectFilePaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject file payment consent system forbidden response has a 4xx status code
func (o *RejectFilePaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject file payment consent system forbidden response has a 5xx status code
func (o *RejectFilePaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject file payment consent system forbidden response a status code equal to that given
func (o *RejectFilePaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

func (o *RejectFilePaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectFilePaymentConsentSystemForbidden) String() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectFilePaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFilePaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFilePaymentConsentSystemNotFound creates a RejectFilePaymentConsentSystemNotFound with default headers values
func NewRejectFilePaymentConsentSystemNotFound() *RejectFilePaymentConsentSystemNotFound {
	return &RejectFilePaymentConsentSystemNotFound{}
}

/*
RejectFilePaymentConsentSystemNotFound describes a response with status code 404, with default header values.

HttpError
*/
type RejectFilePaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject file payment consent system not found response has a 2xx status code
func (o *RejectFilePaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject file payment consent system not found response has a 3xx status code
func (o *RejectFilePaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject file payment consent system not found response has a 4xx status code
func (o *RejectFilePaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject file payment consent system not found response has a 5xx status code
func (o *RejectFilePaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject file payment consent system not found response a status code equal to that given
func (o *RejectFilePaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

func (o *RejectFilePaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectFilePaymentConsentSystemNotFound) String() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectFilePaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFilePaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectFilePaymentConsentSystemTooManyRequests creates a RejectFilePaymentConsentSystemTooManyRequests with default headers values
func NewRejectFilePaymentConsentSystemTooManyRequests() *RejectFilePaymentConsentSystemTooManyRequests {
	return &RejectFilePaymentConsentSystemTooManyRequests{}
}

/*
RejectFilePaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

HttpError
*/
type RejectFilePaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject file payment consent system too many requests response has a 2xx status code
func (o *RejectFilePaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject file payment consent system too many requests response has a 3xx status code
func (o *RejectFilePaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject file payment consent system too many requests response has a 4xx status code
func (o *RejectFilePaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject file payment consent system too many requests response has a 5xx status code
func (o *RejectFilePaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject file payment consent system too many requests response a status code equal to that given
func (o *RejectFilePaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

func (o *RejectFilePaymentConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectFilePaymentConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking/file-payment-consent/{login}/reject][%d] rejectFilePaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectFilePaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectFilePaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
