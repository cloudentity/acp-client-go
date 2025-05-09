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

// AcceptInternationalPaymentConsentSystemReader is a Reader for the AcceptInternationalPaymentConsentSystem structure.
type AcceptInternationalPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AcceptInternationalPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAcceptInternationalPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewAcceptInternationalPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAcceptInternationalPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAcceptInternationalPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAcceptInternationalPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/international-payment-consent/{login}/accept] acceptInternationalPaymentConsentSystem", response, response.Code())
	}
}

// NewAcceptInternationalPaymentConsentSystemOK creates a AcceptInternationalPaymentConsentSystemOK with default headers values
func NewAcceptInternationalPaymentConsentSystemOK() *AcceptInternationalPaymentConsentSystemOK {
	return &AcceptInternationalPaymentConsentSystemOK{}
}

/*
AcceptInternationalPaymentConsentSystemOK describes a response with status code 200, with default header values.

Consent Accepted
*/
type AcceptInternationalPaymentConsentSystemOK struct {
	Payload *models.ConsentAccepted
}

// IsSuccess returns true when this accept international payment consent system o k response has a 2xx status code
func (o *AcceptInternationalPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this accept international payment consent system o k response has a 3xx status code
func (o *AcceptInternationalPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept international payment consent system o k response has a 4xx status code
func (o *AcceptInternationalPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this accept international payment consent system o k response has a 5xx status code
func (o *AcceptInternationalPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this accept international payment consent system o k response a status code equal to that given
func (o *AcceptInternationalPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the accept international payment consent system o k response
func (o *AcceptInternationalPaymentConsentSystemOK) Code() int {
	return 200
}

func (o *AcceptInternationalPaymentConsentSystemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemOK %s", 200, payload)
}

func (o *AcceptInternationalPaymentConsentSystemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemOK %s", 200, payload)
}

func (o *AcceptInternationalPaymentConsentSystemOK) GetPayload() *models.ConsentAccepted {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentAccepted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptInternationalPaymentConsentSystemUnauthorized creates a AcceptInternationalPaymentConsentSystemUnauthorized with default headers values
func NewAcceptInternationalPaymentConsentSystemUnauthorized() *AcceptInternationalPaymentConsentSystemUnauthorized {
	return &AcceptInternationalPaymentConsentSystemUnauthorized{}
}

/*
AcceptInternationalPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type AcceptInternationalPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept international payment consent system unauthorized response has a 2xx status code
func (o *AcceptInternationalPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept international payment consent system unauthorized response has a 3xx status code
func (o *AcceptInternationalPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept international payment consent system unauthorized response has a 4xx status code
func (o *AcceptInternationalPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept international payment consent system unauthorized response has a 5xx status code
func (o *AcceptInternationalPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this accept international payment consent system unauthorized response a status code equal to that given
func (o *AcceptInternationalPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the accept international payment consent system unauthorized response
func (o *AcceptInternationalPaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *AcceptInternationalPaymentConsentSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *AcceptInternationalPaymentConsentSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *AcceptInternationalPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptInternationalPaymentConsentSystemForbidden creates a AcceptInternationalPaymentConsentSystemForbidden with default headers values
func NewAcceptInternationalPaymentConsentSystemForbidden() *AcceptInternationalPaymentConsentSystemForbidden {
	return &AcceptInternationalPaymentConsentSystemForbidden{}
}

/*
AcceptInternationalPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AcceptInternationalPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept international payment consent system forbidden response has a 2xx status code
func (o *AcceptInternationalPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept international payment consent system forbidden response has a 3xx status code
func (o *AcceptInternationalPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept international payment consent system forbidden response has a 4xx status code
func (o *AcceptInternationalPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept international payment consent system forbidden response has a 5xx status code
func (o *AcceptInternationalPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this accept international payment consent system forbidden response a status code equal to that given
func (o *AcceptInternationalPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the accept international payment consent system forbidden response
func (o *AcceptInternationalPaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *AcceptInternationalPaymentConsentSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *AcceptInternationalPaymentConsentSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *AcceptInternationalPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptInternationalPaymentConsentSystemNotFound creates a AcceptInternationalPaymentConsentSystemNotFound with default headers values
func NewAcceptInternationalPaymentConsentSystemNotFound() *AcceptInternationalPaymentConsentSystemNotFound {
	return &AcceptInternationalPaymentConsentSystemNotFound{}
}

/*
AcceptInternationalPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type AcceptInternationalPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept international payment consent system not found response has a 2xx status code
func (o *AcceptInternationalPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept international payment consent system not found response has a 3xx status code
func (o *AcceptInternationalPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept international payment consent system not found response has a 4xx status code
func (o *AcceptInternationalPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept international payment consent system not found response has a 5xx status code
func (o *AcceptInternationalPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this accept international payment consent system not found response a status code equal to that given
func (o *AcceptInternationalPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the accept international payment consent system not found response
func (o *AcceptInternationalPaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *AcceptInternationalPaymentConsentSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *AcceptInternationalPaymentConsentSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *AcceptInternationalPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptInternationalPaymentConsentSystemTooManyRequests creates a AcceptInternationalPaymentConsentSystemTooManyRequests with default headers values
func NewAcceptInternationalPaymentConsentSystemTooManyRequests() *AcceptInternationalPaymentConsentSystemTooManyRequests {
	return &AcceptInternationalPaymentConsentSystemTooManyRequests{}
}

/*
AcceptInternationalPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type AcceptInternationalPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept international payment consent system too many requests response has a 2xx status code
func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept international payment consent system too many requests response has a 3xx status code
func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept international payment consent system too many requests response has a 4xx status code
func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept international payment consent system too many requests response has a 5xx status code
func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this accept international payment consent system too many requests response a status code equal to that given
func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the accept international payment consent system too many requests response
func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/international-payment-consent/{login}/accept][%d] acceptInternationalPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptInternationalPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
