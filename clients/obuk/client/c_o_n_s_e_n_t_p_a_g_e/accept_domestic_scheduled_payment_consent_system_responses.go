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

// AcceptDomesticScheduledPaymentConsentSystemReader is a Reader for the AcceptDomesticScheduledPaymentConsentSystem structure.
type AcceptDomesticScheduledPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AcceptDomesticScheduledPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAcceptDomesticScheduledPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewAcceptDomesticScheduledPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewAcceptDomesticScheduledPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewAcceptDomesticScheduledPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewAcceptDomesticScheduledPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept] acceptDomesticScheduledPaymentConsentSystem", response, response.Code())
	}
}

// NewAcceptDomesticScheduledPaymentConsentSystemOK creates a AcceptDomesticScheduledPaymentConsentSystemOK with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemOK() *AcceptDomesticScheduledPaymentConsentSystemOK {
	return &AcceptDomesticScheduledPaymentConsentSystemOK{}
}

/*
AcceptDomesticScheduledPaymentConsentSystemOK describes a response with status code 200, with default header values.

Consent Accepted
*/
type AcceptDomesticScheduledPaymentConsentSystemOK struct {
	Payload *models.ConsentAccepted
}

// IsSuccess returns true when this accept domestic scheduled payment consent system o k response has a 2xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this accept domestic scheduled payment consent system o k response has a 3xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic scheduled payment consent system o k response has a 4xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this accept domestic scheduled payment consent system o k response has a 5xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic scheduled payment consent system o k response a status code equal to that given
func (o *AcceptDomesticScheduledPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the accept domestic scheduled payment consent system o k response
func (o *AcceptDomesticScheduledPaymentConsentSystemOK) Code() int {
	return 200
}

func (o *AcceptDomesticScheduledPaymentConsentSystemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemOK %s", 200, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemOK %s", 200, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemOK) GetPayload() *models.ConsentAccepted {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ConsentAccepted)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticScheduledPaymentConsentSystemUnauthorized creates a AcceptDomesticScheduledPaymentConsentSystemUnauthorized with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemUnauthorized() *AcceptDomesticScheduledPaymentConsentSystemUnauthorized {
	return &AcceptDomesticScheduledPaymentConsentSystemUnauthorized{}
}

/*
AcceptDomesticScheduledPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type AcceptDomesticScheduledPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic scheduled payment consent system unauthorized response has a 2xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic scheduled payment consent system unauthorized response has a 3xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic scheduled payment consent system unauthorized response has a 4xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic scheduled payment consent system unauthorized response has a 5xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic scheduled payment consent system unauthorized response a status code equal to that given
func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the accept domestic scheduled payment consent system unauthorized response
func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticScheduledPaymentConsentSystemForbidden creates a AcceptDomesticScheduledPaymentConsentSystemForbidden with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemForbidden() *AcceptDomesticScheduledPaymentConsentSystemForbidden {
	return &AcceptDomesticScheduledPaymentConsentSystemForbidden{}
}

/*
AcceptDomesticScheduledPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type AcceptDomesticScheduledPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic scheduled payment consent system forbidden response has a 2xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic scheduled payment consent system forbidden response has a 3xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic scheduled payment consent system forbidden response has a 4xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic scheduled payment consent system forbidden response has a 5xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic scheduled payment consent system forbidden response a status code equal to that given
func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the accept domestic scheduled payment consent system forbidden response
func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticScheduledPaymentConsentSystemNotFound creates a AcceptDomesticScheduledPaymentConsentSystemNotFound with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemNotFound() *AcceptDomesticScheduledPaymentConsentSystemNotFound {
	return &AcceptDomesticScheduledPaymentConsentSystemNotFound{}
}

/*
AcceptDomesticScheduledPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type AcceptDomesticScheduledPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic scheduled payment consent system not found response has a 2xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic scheduled payment consent system not found response has a 3xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic scheduled payment consent system not found response has a 4xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic scheduled payment consent system not found response has a 5xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic scheduled payment consent system not found response a status code equal to that given
func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the accept domestic scheduled payment consent system not found response
func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAcceptDomesticScheduledPaymentConsentSystemTooManyRequests creates a AcceptDomesticScheduledPaymentConsentSystemTooManyRequests with default headers values
func NewAcceptDomesticScheduledPaymentConsentSystemTooManyRequests() *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests {
	return &AcceptDomesticScheduledPaymentConsentSystemTooManyRequests{}
}

/*
AcceptDomesticScheduledPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type AcceptDomesticScheduledPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this accept domestic scheduled payment consent system too many requests response has a 2xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this accept domestic scheduled payment consent system too many requests response has a 3xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this accept domestic scheduled payment consent system too many requests response has a 4xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this accept domestic scheduled payment consent system too many requests response has a 5xx status code
func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this accept domestic scheduled payment consent system too many requests response a status code equal to that given
func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the accept domestic scheduled payment consent system too many requests response
func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /open-banking/domestic-scheduled-payment-consent/{login}/accept][%d] acceptDomesticScheduledPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *AcceptDomesticScheduledPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
