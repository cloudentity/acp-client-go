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

	"github.com/cloudentity/acp-client-go/clients/obbr/models"
)

// RejectOBBRCustomerPaymentConsentSystemReader is a Reader for the RejectOBBRCustomerPaymentConsentSystem structure.
type RejectOBBRCustomerPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RejectOBBRCustomerPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRejectOBBRCustomerPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewRejectOBBRCustomerPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewRejectOBBRCustomerPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewRejectOBBRCustomerPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewRejectOBBRCustomerPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking-brasil/payment/{login}/reject] rejectOBBRCustomerPaymentConsentSystem", response, response.Code())
	}
}

// NewRejectOBBRCustomerPaymentConsentSystemOK creates a RejectOBBRCustomerPaymentConsentSystemOK with default headers values
func NewRejectOBBRCustomerPaymentConsentSystemOK() *RejectOBBRCustomerPaymentConsentSystemOK {
	return &RejectOBBRCustomerPaymentConsentSystemOK{}
}

/*
RejectOBBRCustomerPaymentConsentSystemOK describes a response with status code 200, with default header values.

Consent rejected
*/
type RejectOBBRCustomerPaymentConsentSystemOK struct {
	Payload *models.ConsentRejected
}

// IsSuccess returns true when this reject o b b r customer payment consent system o k response has a 2xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this reject o b b r customer payment consent system o k response has a 3xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer payment consent system o k response has a 4xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this reject o b b r customer payment consent system o k response has a 5xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer payment consent system o k response a status code equal to that given
func (o *RejectOBBRCustomerPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the reject o b b r customer payment consent system o k response
func (o *RejectOBBRCustomerPaymentConsentSystemOK) Code() int {
	return 200
}

func (o *RejectOBBRCustomerPaymentConsentSystemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemOK %s", 200, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemOK %s", 200, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemOK) GetPayload() *models.ConsentRejected {
	return o.Payload
}

func (o *RejectOBBRCustomerPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentRejected)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerPaymentConsentSystemUnauthorized creates a RejectOBBRCustomerPaymentConsentSystemUnauthorized with default headers values
func NewRejectOBBRCustomerPaymentConsentSystemUnauthorized() *RejectOBBRCustomerPaymentConsentSystemUnauthorized {
	return &RejectOBBRCustomerPaymentConsentSystemUnauthorized{}
}

/*
RejectOBBRCustomerPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type RejectOBBRCustomerPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer payment consent system unauthorized response has a 2xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer payment consent system unauthorized response has a 3xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer payment consent system unauthorized response has a 4xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer payment consent system unauthorized response has a 5xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer payment consent system unauthorized response a status code equal to that given
func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the reject o b b r customer payment consent system unauthorized response
func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerPaymentConsentSystemForbidden creates a RejectOBBRCustomerPaymentConsentSystemForbidden with default headers values
func NewRejectOBBRCustomerPaymentConsentSystemForbidden() *RejectOBBRCustomerPaymentConsentSystemForbidden {
	return &RejectOBBRCustomerPaymentConsentSystemForbidden{}
}

/*
RejectOBBRCustomerPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type RejectOBBRCustomerPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer payment consent system forbidden response has a 2xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer payment consent system forbidden response has a 3xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer payment consent system forbidden response has a 4xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer payment consent system forbidden response has a 5xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer payment consent system forbidden response a status code equal to that given
func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the reject o b b r customer payment consent system forbidden response
func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerPaymentConsentSystemNotFound creates a RejectOBBRCustomerPaymentConsentSystemNotFound with default headers values
func NewRejectOBBRCustomerPaymentConsentSystemNotFound() *RejectOBBRCustomerPaymentConsentSystemNotFound {
	return &RejectOBBRCustomerPaymentConsentSystemNotFound{}
}

/*
RejectOBBRCustomerPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type RejectOBBRCustomerPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer payment consent system not found response has a 2xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer payment consent system not found response has a 3xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer payment consent system not found response has a 4xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer payment consent system not found response has a 5xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer payment consent system not found response a status code equal to that given
func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the reject o b b r customer payment consent system not found response
func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRejectOBBRCustomerPaymentConsentSystemTooManyRequests creates a RejectOBBRCustomerPaymentConsentSystemTooManyRequests with default headers values
func NewRejectOBBRCustomerPaymentConsentSystemTooManyRequests() *RejectOBBRCustomerPaymentConsentSystemTooManyRequests {
	return &RejectOBBRCustomerPaymentConsentSystemTooManyRequests{}
}

/*
RejectOBBRCustomerPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type RejectOBBRCustomerPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this reject o b b r customer payment consent system too many requests response has a 2xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this reject o b b r customer payment consent system too many requests response has a 3xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this reject o b b r customer payment consent system too many requests response has a 4xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this reject o b b r customer payment consent system too many requests response has a 5xx status code
func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this reject o b b r customer payment consent system too many requests response a status code equal to that given
func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the reject o b b r customer payment consent system too many requests response
func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking-brasil/payment/{login}/reject][%d] rejectOBBRCustomerPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *RejectOBBRCustomerPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
