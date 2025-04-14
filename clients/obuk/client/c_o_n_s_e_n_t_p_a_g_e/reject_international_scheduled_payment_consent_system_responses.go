// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// RejectInternationalScheduledPaymentConsentSystemReader is a Reader for the RejectInternationalScheduledPaymentConsentSystem structure.
type RejectInternationalScheduledPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectInternationalScheduledPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectInternationalScheduledPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectInternationalScheduledPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectInternationalScheduledPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectInternationalScheduledPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectInternationalScheduledPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/international-scheduled-payment-consent/{login}/reject] rejectInternationalScheduledPaymentConsentSystem", response, response.Code())
	}
}

// NewRejectInternationalScheduledPaymentConsentSystemOK creates a RejectInternationalScheduledPaymentConsentSystemOK with default headers values
func NewRejectInternationalScheduledPaymentConsentSystemOK() *RejectInternationalScheduledPaymentConsentSystemOK {
	return &RejectInternationalScheduledPaymentConsentSystemOK{}
}

/*
RejectInternationalScheduledPaymentConsentSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectInternationalScheduledPaymentConsentSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject international scheduled payment consent system o k response has a 2xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject international scheduled payment consent system o k response has a 3xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international scheduled payment consent system o k response has a 4xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject international scheduled payment consent system o k response has a 5xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international scheduled payment consent system o k response a status code equal to that given
func (o *RejectInternationalScheduledPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reject international scheduled payment consent system o k response
func (o *RejectInternationalScheduledPaymentConsentSystemOK) Code() int {
	return 200
}

func (o *RejectInternationalScheduledPaymentConsentSystemOK) Error() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemOK) String() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemOK  %+v", 200, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectInternationalScheduledPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalScheduledPaymentConsentSystemUnauthorized creates a RejectInternationalScheduledPaymentConsentSystemUnauthorized with default headers values
func NewRejectInternationalScheduledPaymentConsentSystemUnauthorized() *RejectInternationalScheduledPaymentConsentSystemUnauthorized {
	return &RejectInternationalScheduledPaymentConsentSystemUnauthorized{}
}

/*
RejectInternationalScheduledPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RejectInternationalScheduledPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international scheduled payment consent system unauthorized response has a 2xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international scheduled payment consent system unauthorized response has a 3xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international scheduled payment consent system unauthorized response has a 4xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international scheduled payment consent system unauthorized response has a 5xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international scheduled payment consent system unauthorized response a status code equal to that given
func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the reject international scheduled payment consent system unauthorized response
func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) Error() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) String() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemUnauthorized  %+v", 401, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalScheduledPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalScheduledPaymentConsentSystemForbidden creates a RejectInternationalScheduledPaymentConsentSystemForbidden with default headers values
func NewRejectInternationalScheduledPaymentConsentSystemForbidden() *RejectInternationalScheduledPaymentConsentSystemForbidden {
	return &RejectInternationalScheduledPaymentConsentSystemForbidden{}
}

/*
RejectInternationalScheduledPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RejectInternationalScheduledPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international scheduled payment consent system forbidden response has a 2xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international scheduled payment consent system forbidden response has a 3xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international scheduled payment consent system forbidden response has a 4xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international scheduled payment consent system forbidden response has a 5xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international scheduled payment consent system forbidden response a status code equal to that given
func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the reject international scheduled payment consent system forbidden response
func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) Error() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) String() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemForbidden  %+v", 403, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalScheduledPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalScheduledPaymentConsentSystemNotFound creates a RejectInternationalScheduledPaymentConsentSystemNotFound with default headers values
func NewRejectInternationalScheduledPaymentConsentSystemNotFound() *RejectInternationalScheduledPaymentConsentSystemNotFound {
	return &RejectInternationalScheduledPaymentConsentSystemNotFound{}
}

/*
RejectInternationalScheduledPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type RejectInternationalScheduledPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international scheduled payment consent system not found response has a 2xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international scheduled payment consent system not found response has a 3xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international scheduled payment consent system not found response has a 4xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international scheduled payment consent system not found response has a 5xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international scheduled payment consent system not found response a status code equal to that given
func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the reject international scheduled payment consent system not found response
func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) Error() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) String() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemNotFound  %+v", 404, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalScheduledPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalScheduledPaymentConsentSystemTooManyRequests creates a RejectInternationalScheduledPaymentConsentSystemTooManyRequests with default headers values
func NewRejectInternationalScheduledPaymentConsentSystemTooManyRequests() *RejectInternationalScheduledPaymentConsentSystemTooManyRequests {
	return &RejectInternationalScheduledPaymentConsentSystemTooManyRequests{}
}

/*
RejectInternationalScheduledPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RejectInternationalScheduledPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international scheduled payment consent system too many requests response has a 2xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international scheduled payment consent system too many requests response has a 3xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international scheduled payment consent system too many requests response has a 4xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international scheduled payment consent system too many requests response has a 5xx status code
func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international scheduled payment consent system too many requests response a status code equal to that given
func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the reject international scheduled payment consent system too many requests response
func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) Error() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) String() string {
	return fmt.Sprintf("[POST /open-banking/international-scheduled-payment-consent/{login}/reject][%d] rejectInternationalScheduledPaymentConsentSystemTooManyRequests  %+v", 429, o.Payload)
}

func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalScheduledPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
