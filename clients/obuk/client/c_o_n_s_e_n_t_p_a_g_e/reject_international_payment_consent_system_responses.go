// Code generated by go-swagger; DO NOT EDIT.

package c_o_n_s_e_n_t_p_a_g_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/cloudentity/acp-client-go/clients/obuk/models"
)

// RejectInternationalPaymentConsentSystemReader is a Reader for the RejectInternationalPaymentConsentSystem structure.
type RejectInternationalPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectInternationalPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectInternationalPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectInternationalPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectInternationalPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectInternationalPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectInternationalPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/international-payment-consent/{login}/reject] rejectInternationalPaymentConsentSystem", response, response.Code())
	}
}

// NewRejectInternationalPaymentConsentSystemOK creates a RejectInternationalPaymentConsentSystemOK with default headers values
func NewRejectInternationalPaymentConsentSystemOK() *RejectInternationalPaymentConsentSystemOK {
	return &RejectInternationalPaymentConsentSystemOK{}
}

/*
RejectInternationalPaymentConsentSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectInternationalPaymentConsentSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject international payment consent system o k response has a 2xx status code
func (o *RejectInternationalPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject international payment consent system o k response has a 3xx status code
func (o *RejectInternationalPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international payment consent system o k response has a 4xx status code
func (o *RejectInternationalPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject international payment consent system o k response has a 5xx status code
func (o *RejectInternationalPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international payment consent system o k response a status code equal to that given
func (o *RejectInternationalPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reject international payment consent system o k response
func (o *RejectInternationalPaymentConsentSystemOK) Code() int {
	return 200
}

func (o *RejectInternationalPaymentConsentSystemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemOK %s", 200, payload)
}

func (o *RejectInternationalPaymentConsentSystemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemOK %s", 200, payload)
}

func (o *RejectInternationalPaymentConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalPaymentConsentSystemUnauthorized creates a RejectInternationalPaymentConsentSystemUnauthorized with default headers values
func NewRejectInternationalPaymentConsentSystemUnauthorized() *RejectInternationalPaymentConsentSystemUnauthorized {
	return &RejectInternationalPaymentConsentSystemUnauthorized{}
}

/*
RejectInternationalPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RejectInternationalPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international payment consent system unauthorized response has a 2xx status code
func (o *RejectInternationalPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international payment consent system unauthorized response has a 3xx status code
func (o *RejectInternationalPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international payment consent system unauthorized response has a 4xx status code
func (o *RejectInternationalPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international payment consent system unauthorized response has a 5xx status code
func (o *RejectInternationalPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international payment consent system unauthorized response a status code equal to that given
func (o *RejectInternationalPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the reject international payment consent system unauthorized response
func (o *RejectInternationalPaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *RejectInternationalPaymentConsentSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *RejectInternationalPaymentConsentSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *RejectInternationalPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalPaymentConsentSystemForbidden creates a RejectInternationalPaymentConsentSystemForbidden with default headers values
func NewRejectInternationalPaymentConsentSystemForbidden() *RejectInternationalPaymentConsentSystemForbidden {
	return &RejectInternationalPaymentConsentSystemForbidden{}
}

/*
RejectInternationalPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RejectInternationalPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international payment consent system forbidden response has a 2xx status code
func (o *RejectInternationalPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international payment consent system forbidden response has a 3xx status code
func (o *RejectInternationalPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international payment consent system forbidden response has a 4xx status code
func (o *RejectInternationalPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international payment consent system forbidden response has a 5xx status code
func (o *RejectInternationalPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international payment consent system forbidden response a status code equal to that given
func (o *RejectInternationalPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the reject international payment consent system forbidden response
func (o *RejectInternationalPaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *RejectInternationalPaymentConsentSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *RejectInternationalPaymentConsentSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *RejectInternationalPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalPaymentConsentSystemNotFound creates a RejectInternationalPaymentConsentSystemNotFound with default headers values
func NewRejectInternationalPaymentConsentSystemNotFound() *RejectInternationalPaymentConsentSystemNotFound {
	return &RejectInternationalPaymentConsentSystemNotFound{}
}

/*
RejectInternationalPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type RejectInternationalPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international payment consent system not found response has a 2xx status code
func (o *RejectInternationalPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international payment consent system not found response has a 3xx status code
func (o *RejectInternationalPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international payment consent system not found response has a 4xx status code
func (o *RejectInternationalPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international payment consent system not found response has a 5xx status code
func (o *RejectInternationalPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international payment consent system not found response a status code equal to that given
func (o *RejectInternationalPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the reject international payment consent system not found response
func (o *RejectInternationalPaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *RejectInternationalPaymentConsentSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *RejectInternationalPaymentConsentSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *RejectInternationalPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectInternationalPaymentConsentSystemTooManyRequests creates a RejectInternationalPaymentConsentSystemTooManyRequests with default headers values
func NewRejectInternationalPaymentConsentSystemTooManyRequests() *RejectInternationalPaymentConsentSystemTooManyRequests {
	return &RejectInternationalPaymentConsentSystemTooManyRequests{}
}

/*
RejectInternationalPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RejectInternationalPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject international payment consent system too many requests response has a 2xx status code
func (o *RejectInternationalPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject international payment consent system too many requests response has a 3xx status code
func (o *RejectInternationalPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject international payment consent system too many requests response has a 4xx status code
func (o *RejectInternationalPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject international payment consent system too many requests response has a 5xx status code
func (o *RejectInternationalPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject international payment consent system too many requests response a status code equal to that given
func (o *RejectInternationalPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the reject international payment consent system too many requests response
func (o *RejectInternationalPaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *RejectInternationalPaymentConsentSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *RejectInternationalPaymentConsentSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/reject][%d] rejectInternationalPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *RejectInternationalPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectInternationalPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
