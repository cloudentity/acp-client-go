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

// GetDomesticPaymentConsentSystemReader is a Reader for the GetDomesticPaymentConsentSystem structure.
type GetDomesticPaymentConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetDomesticPaymentConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetDomesticPaymentConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetDomesticPaymentConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetDomesticPaymentConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetDomesticPaymentConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetDomesticPaymentConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /open-banking/domestic-payment-consent/{login}] getDomesticPaymentConsentSystem", response, response.Code())
	}
}

// NewGetDomesticPaymentConsentSystemOK creates a GetDomesticPaymentConsentSystemOK with default headers values
func NewGetDomesticPaymentConsentSystemOK() *GetDomesticPaymentConsentSystemOK {
	return &GetDomesticPaymentConsentSystemOK{}
}

/*
GetDomesticPaymentConsentSystemOK describes a response with status code 200, with default header values.

GetDomesticPaymentConsentResponse
*/
type GetDomesticPaymentConsentSystemOK struct {
	Payload *models.GetDomesticPaymentConsentResponse
}

// IsSuccess returns true when this get domestic payment consent system o k response has a 2xx status code
func (o *GetDomesticPaymentConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get domestic payment consent system o k response has a 3xx status code
func (o *GetDomesticPaymentConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic payment consent system o k response has a 4xx status code
func (o *GetDomesticPaymentConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get domestic payment consent system o k response has a 5xx status code
func (o *GetDomesticPaymentConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic payment consent system o k response a status code equal to that given
func (o *GetDomesticPaymentConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get domestic payment consent system o k response
func (o *GetDomesticPaymentConsentSystemOK) Code() int {
	return 200
}

func (o *GetDomesticPaymentConsentSystemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemOK %s", 200, payload)
}

func (o *GetDomesticPaymentConsentSystemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemOK %s", 200, payload)
}

func (o *GetDomesticPaymentConsentSystemOK) GetPayload() *models.GetDomesticPaymentConsentResponse {
	return o.Payload
}

func (o *GetDomesticPaymentConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetDomesticPaymentConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticPaymentConsentSystemUnauthorized creates a GetDomesticPaymentConsentSystemUnauthorized with default headers values
func NewGetDomesticPaymentConsentSystemUnauthorized() *GetDomesticPaymentConsentSystemUnauthorized {
	return &GetDomesticPaymentConsentSystemUnauthorized{}
}

/*
GetDomesticPaymentConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetDomesticPaymentConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic payment consent system unauthorized response has a 2xx status code
func (o *GetDomesticPaymentConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic payment consent system unauthorized response has a 3xx status code
func (o *GetDomesticPaymentConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic payment consent system unauthorized response has a 4xx status code
func (o *GetDomesticPaymentConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic payment consent system unauthorized response has a 5xx status code
func (o *GetDomesticPaymentConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic payment consent system unauthorized response a status code equal to that given
func (o *GetDomesticPaymentConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get domestic payment consent system unauthorized response
func (o *GetDomesticPaymentConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *GetDomesticPaymentConsentSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *GetDomesticPaymentConsentSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemUnauthorized %s", 401, payload)
}

func (o *GetDomesticPaymentConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticPaymentConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticPaymentConsentSystemForbidden creates a GetDomesticPaymentConsentSystemForbidden with default headers values
func NewGetDomesticPaymentConsentSystemForbidden() *GetDomesticPaymentConsentSystemForbidden {
	return &GetDomesticPaymentConsentSystemForbidden{}
}

/*
GetDomesticPaymentConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetDomesticPaymentConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic payment consent system forbidden response has a 2xx status code
func (o *GetDomesticPaymentConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic payment consent system forbidden response has a 3xx status code
func (o *GetDomesticPaymentConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic payment consent system forbidden response has a 4xx status code
func (o *GetDomesticPaymentConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic payment consent system forbidden response has a 5xx status code
func (o *GetDomesticPaymentConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic payment consent system forbidden response a status code equal to that given
func (o *GetDomesticPaymentConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get domestic payment consent system forbidden response
func (o *GetDomesticPaymentConsentSystemForbidden) Code() int {
	return 403
}

func (o *GetDomesticPaymentConsentSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *GetDomesticPaymentConsentSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemForbidden %s", 403, payload)
}

func (o *GetDomesticPaymentConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticPaymentConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticPaymentConsentSystemNotFound creates a GetDomesticPaymentConsentSystemNotFound with default headers values
func NewGetDomesticPaymentConsentSystemNotFound() *GetDomesticPaymentConsentSystemNotFound {
	return &GetDomesticPaymentConsentSystemNotFound{}
}

/*
GetDomesticPaymentConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetDomesticPaymentConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic payment consent system not found response has a 2xx status code
func (o *GetDomesticPaymentConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic payment consent system not found response has a 3xx status code
func (o *GetDomesticPaymentConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic payment consent system not found response has a 4xx status code
func (o *GetDomesticPaymentConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic payment consent system not found response has a 5xx status code
func (o *GetDomesticPaymentConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic payment consent system not found response a status code equal to that given
func (o *GetDomesticPaymentConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get domestic payment consent system not found response
func (o *GetDomesticPaymentConsentSystemNotFound) Code() int {
	return 404
}

func (o *GetDomesticPaymentConsentSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *GetDomesticPaymentConsentSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemNotFound %s", 404, payload)
}

func (o *GetDomesticPaymentConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticPaymentConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetDomesticPaymentConsentSystemTooManyRequests creates a GetDomesticPaymentConsentSystemTooManyRequests with default headers values
func NewGetDomesticPaymentConsentSystemTooManyRequests() *GetDomesticPaymentConsentSystemTooManyRequests {
	return &GetDomesticPaymentConsentSystemTooManyRequests{}
}

/*
GetDomesticPaymentConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetDomesticPaymentConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get domestic payment consent system too many requests response has a 2xx status code
func (o *GetDomesticPaymentConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get domestic payment consent system too many requests response has a 3xx status code
func (o *GetDomesticPaymentConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get domestic payment consent system too many requests response has a 4xx status code
func (o *GetDomesticPaymentConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get domestic payment consent system too many requests response has a 5xx status code
func (o *GetDomesticPaymentConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get domestic payment consent system too many requests response a status code equal to that given
func (o *GetDomesticPaymentConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get domestic payment consent system too many requests response
func (o *GetDomesticPaymentConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *GetDomesticPaymentConsentSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *GetDomesticPaymentConsentSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/domestic-payment-consent/{login}][%d] getDomesticPaymentConsentSystemTooManyRequests %s", 429, payload)
}

func (o *GetDomesticPaymentConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetDomesticPaymentConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
