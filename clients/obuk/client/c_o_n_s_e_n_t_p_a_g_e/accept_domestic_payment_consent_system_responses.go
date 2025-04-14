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

// AcceptDomesticPaymentConsentSystemReader is a Reader for the AcceptDomesticPaymentConsentSystem structure.
type AcceptDomesticPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AcceptDomesticPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAcceptDomesticPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewAcceptDomesticPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAcceptDomesticPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAcceptDomesticPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAcceptDomesticPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/domestic-payment-consent/{login}/accept] acceptDomesticPaymentConsentSystem", response, response.Code())
	}
}

// NewAcceptDomesticPaymentConsentSystemOK creates a AcceptDomesticPaymentConsentSystemOK with default headers values
func NewAcceptDomesticPaymentConsentSystemOK() *AcceptDomesticPaymentConsentSystemOK {
	return &AcceptDomesticPaymentConsentSystemOK{}
}

/*
AcceptDomesticPaymentConsentSystemOK describes a response with status code 200, with default header values.

Consent Accepted
*/
type AcceptDomesticPaymentConsentSystemOK struct {
	Payload *models.ConsentAccepted
}

// IsSuccess returns true when this accept domestic payment consent system o k response has a 2xx status code
func (o *AcceptDomesticPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this accept domestic payment consent system o k response has a 3xx status code
func (o *AcceptDomesticPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic payment consent system o k response has a 4xx status code
func (o *AcceptDomesticPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this accept domestic payment consent system o k response has a 5xx status code
func (o *AcceptDomesticPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic payment consent system o k response a status code equal to that given
func (o *AcceptDomesticPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the accept domestic payment consent system o k response
func (o *AcceptDomesticPaymentConsentSystemOK) Code() int {
	return 200
}

func (o *AcceptDomesticPaymentConsentSystemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemOK %s", 200, payload)
}

func (o *AcceptDomesticPaymentConsentSystemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemOK %s", 200, payload)
}

func (o *AcceptDomesticPaymentConsentSystemOK) GetPayload() *models.ConsentAccepted {
	return o.Payload
}

func (o *AcceptDomesticPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentAccepted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticPaymentConsentSystemUnauthorized creates a AcceptDomesticPaymentConsentSystemUnauthorized with default headers values
func NewAcceptDomesticPaymentConsentSystemUnauthorized() *AcceptDomesticPaymentConsentSystemUnauthorized {
	return &AcceptDomesticPaymentConsentSystemUnauthorized{}
}

/*
AcceptDomesticPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type AcceptDomesticPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic payment consent system unauthorized response has a 2xx status code
func (o *AcceptDomesticPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic payment consent system unauthorized response has a 3xx status code
func (o *AcceptDomesticPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic payment consent system unauthorized response has a 4xx status code
func (o *AcceptDomesticPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic payment consent system unauthorized response has a 5xx status code
func (o *AcceptDomesticPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic payment consent system unauthorized response a status code equal to that given
func (o *AcceptDomesticPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the accept domestic payment consent system unauthorized response
func (o *AcceptDomesticPaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *AcceptDomesticPaymentConsentSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *AcceptDomesticPaymentConsentSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *AcceptDomesticPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticPaymentConsentSystemForbidden creates a AcceptDomesticPaymentConsentSystemForbidden with default headers values
func NewAcceptDomesticPaymentConsentSystemForbidden() *AcceptDomesticPaymentConsentSystemForbidden {
	return &AcceptDomesticPaymentConsentSystemForbidden{}
}

/*
AcceptDomesticPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AcceptDomesticPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic payment consent system forbidden response has a 2xx status code
func (o *AcceptDomesticPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic payment consent system forbidden response has a 3xx status code
func (o *AcceptDomesticPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic payment consent system forbidden response has a 4xx status code
func (o *AcceptDomesticPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic payment consent system forbidden response has a 5xx status code
func (o *AcceptDomesticPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic payment consent system forbidden response a status code equal to that given
func (o *AcceptDomesticPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the accept domestic payment consent system forbidden response
func (o *AcceptDomesticPaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *AcceptDomesticPaymentConsentSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *AcceptDomesticPaymentConsentSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *AcceptDomesticPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticPaymentConsentSystemNotFound creates a AcceptDomesticPaymentConsentSystemNotFound with default headers values
func NewAcceptDomesticPaymentConsentSystemNotFound() *AcceptDomesticPaymentConsentSystemNotFound {
	return &AcceptDomesticPaymentConsentSystemNotFound{}
}

/*
AcceptDomesticPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type AcceptDomesticPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic payment consent system not found response has a 2xx status code
func (o *AcceptDomesticPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic payment consent system not found response has a 3xx status code
func (o *AcceptDomesticPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic payment consent system not found response has a 4xx status code
func (o *AcceptDomesticPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic payment consent system not found response has a 5xx status code
func (o *AcceptDomesticPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic payment consent system not found response a status code equal to that given
func (o *AcceptDomesticPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the accept domestic payment consent system not found response
func (o *AcceptDomesticPaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *AcceptDomesticPaymentConsentSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *AcceptDomesticPaymentConsentSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *AcceptDomesticPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticPaymentConsentSystemTooManyRequests creates a AcceptDomesticPaymentConsentSystemTooManyRequests with default headers values
func NewAcceptDomesticPaymentConsentSystemTooManyRequests() *AcceptDomesticPaymentConsentSystemTooManyRequests {
	return &AcceptDomesticPaymentConsentSystemTooManyRequests{}
}

/*
AcceptDomesticPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type AcceptDomesticPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic payment consent system too many requests response has a 2xx status code
func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic payment consent system too many requests response has a 3xx status code
func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic payment consent system too many requests response has a 4xx status code
func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic payment consent system too many requests response has a 5xx status code
func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic payment consent system too many requests response a status code equal to that given
func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the accept domestic payment consent system too many requests response
func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-payment-consent/{login}/accept][%d] acceptDomesticPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
