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

// GetInternationalStandingOrderConsentSystemReader is a Reader for the GetInternationalStandingOrderConsentSystem structure.
type GetInternationalStandingOrderConsentSystemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetInternationalStandingOrderConsentSystemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetInternationalStandingOrderConsentSystemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewGetInternationalStandingOrderConsentSystemUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 403:
		result := NewGetInternationalStandingOrderConsentSystemForbidden()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewGetInternationalStandingOrderConsentSystemNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 429:
		result := NewGetInternationalStandingOrderConsentSystemTooManyRequests()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("[GET /open-banking/international-standing-order-consent/{login}] getInternationalStandingOrderConsentSystem", response, response.Code())
	}
}

// NewGetInternationalStandingOrderConsentSystemOK creates a GetInternationalStandingOrderConsentSystemOK with default headers values
func NewGetInternationalStandingOrderConsentSystemOK() *GetInternationalStandingOrderConsentSystemOK {
	return &GetInternationalStandingOrderConsentSystemOK{}
}

/*
GetInternationalStandingOrderConsentSystemOK describes a response with status code 200, with default header values.

GetInternationalStandingOrderConsentResponse
*/
type GetInternationalStandingOrderConsentSystemOK struct {
	Payload *models.GetInternationalStandingOrderConsentResponse
}

// IsSuccess returns true when this get international standing order consent system o k response has a 2xx status code
func (o *GetInternationalStandingOrderConsentSystemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get international standing order consent system o k response has a 3xx status code
func (o *GetInternationalStandingOrderConsentSystemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent system o k response has a 4xx status code
func (o *GetInternationalStandingOrderConsentSystemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get international standing order consent system o k response has a 5xx status code
func (o *GetInternationalStandingOrderConsentSystemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent system o k response a status code equal to that given
func (o *GetInternationalStandingOrderConsentSystemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get international standing order consent system o k response
func (o *GetInternationalStandingOrderConsentSystemOK) Code() int {
	return 200
}

func (o *GetInternationalStandingOrderConsentSystemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemOK %s", 200, payload)
}

func (o *GetInternationalStandingOrderConsentSystemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemOK %s", 200, payload)
}

func (o *GetInternationalStandingOrderConsentSystemOK) GetPayload() *models.GetInternationalStandingOrderConsentResponse {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GetInternationalStandingOrderConsentResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentSystemUnauthorized creates a GetInternationalStandingOrderConsentSystemUnauthorized with default headers values
func NewGetInternationalStandingOrderConsentSystemUnauthorized() *GetInternationalStandingOrderConsentSystemUnauthorized {
	return &GetInternationalStandingOrderConsentSystemUnauthorized{}
}

/*
GetInternationalStandingOrderConsentSystemUnauthorized describes a response with status code 401, with default header values.

Unauthorized
*/
type GetInternationalStandingOrderConsentSystemUnauthorized struct {
	Payload *models.Error
}

// IsSuccess returns true when this get international standing order consent system unauthorized response has a 2xx status code
func (o *GetInternationalStandingOrderConsentSystemUnauthorized) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent system unauthorized response has a 3xx status code
func (o *GetInternationalStandingOrderConsentSystemUnauthorized) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent system unauthorized response has a 4xx status code
func (o *GetInternationalStandingOrderConsentSystemUnauthorized) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent system unauthorized response has a 5xx status code
func (o *GetInternationalStandingOrderConsentSystemUnauthorized) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent system unauthorized response a status code equal to that given
func (o *GetInternationalStandingOrderConsentSystemUnauthorized) IsCode(code int) bool {
	return code == 401
}

// Code gets the status code for the get international standing order consent system unauthorized response
func (o *GetInternationalStandingOrderConsentSystemUnauthorized) Code() int {
	return 401
}

func (o *GetInternationalStandingOrderConsentSystemUnauthorized) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemUnauthorized %s", 401, payload)
}

func (o *GetInternationalStandingOrderConsentSystemUnauthorized) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemUnauthorized %s", 401, payload)
}

func (o *GetInternationalStandingOrderConsentSystemUnauthorized) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentSystemForbidden creates a GetInternationalStandingOrderConsentSystemForbidden with default headers values
func NewGetInternationalStandingOrderConsentSystemForbidden() *GetInternationalStandingOrderConsentSystemForbidden {
	return &GetInternationalStandingOrderConsentSystemForbidden{}
}

/*
GetInternationalStandingOrderConsentSystemForbidden describes a response with status code 403, with default header values.

Forbidden
*/
type GetInternationalStandingOrderConsentSystemForbidden struct {
	Payload *models.Error
}

// IsSuccess returns true when this get international standing order consent system forbidden response has a 2xx status code
func (o *GetInternationalStandingOrderConsentSystemForbidden) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent system forbidden response has a 3xx status code
func (o *GetInternationalStandingOrderConsentSystemForbidden) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent system forbidden response has a 4xx status code
func (o *GetInternationalStandingOrderConsentSystemForbidden) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent system forbidden response has a 5xx status code
func (o *GetInternationalStandingOrderConsentSystemForbidden) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent system forbidden response a status code equal to that given
func (o *GetInternationalStandingOrderConsentSystemForbidden) IsCode(code int) bool {
	return code == 403
}

// Code gets the status code for the get international standing order consent system forbidden response
func (o *GetInternationalStandingOrderConsentSystemForbidden) Code() int {
	return 403
}

func (o *GetInternationalStandingOrderConsentSystemForbidden) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemForbidden %s", 403, payload)
}

func (o *GetInternationalStandingOrderConsentSystemForbidden) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemForbidden %s", 403, payload)
}

func (o *GetInternationalStandingOrderConsentSystemForbidden) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemForbidden) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentSystemNotFound creates a GetInternationalStandingOrderConsentSystemNotFound with default headers values
func NewGetInternationalStandingOrderConsentSystemNotFound() *GetInternationalStandingOrderConsentSystemNotFound {
	return &GetInternationalStandingOrderConsentSystemNotFound{}
}

/*
GetInternationalStandingOrderConsentSystemNotFound describes a response with status code 404, with default header values.

Not found
*/
type GetInternationalStandingOrderConsentSystemNotFound struct {
	Payload *models.Error
}

// IsSuccess returns true when this get international standing order consent system not found response has a 2xx status code
func (o *GetInternationalStandingOrderConsentSystemNotFound) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent system not found response has a 3xx status code
func (o *GetInternationalStandingOrderConsentSystemNotFound) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent system not found response has a 4xx status code
func (o *GetInternationalStandingOrderConsentSystemNotFound) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent system not found response has a 5xx status code
func (o *GetInternationalStandingOrderConsentSystemNotFound) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent system not found response a status code equal to that given
func (o *GetInternationalStandingOrderConsentSystemNotFound) IsCode(code int) bool {
	return code == 404
}

// Code gets the status code for the get international standing order consent system not found response
func (o *GetInternationalStandingOrderConsentSystemNotFound) Code() int {
	return 404
}

func (o *GetInternationalStandingOrderConsentSystemNotFound) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemNotFound %s", 404, payload)
}

func (o *GetInternationalStandingOrderConsentSystemNotFound) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemNotFound %s", 404, payload)
}

func (o *GetInternationalStandingOrderConsentSystemNotFound) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetInternationalStandingOrderConsentSystemTooManyRequests creates a GetInternationalStandingOrderConsentSystemTooManyRequests with default headers values
func NewGetInternationalStandingOrderConsentSystemTooManyRequests() *GetInternationalStandingOrderConsentSystemTooManyRequests {
	return &GetInternationalStandingOrderConsentSystemTooManyRequests{}
}

/*
GetInternationalStandingOrderConsentSystemTooManyRequests describes a response with status code 429, with default header values.

Too many requests
*/
type GetInternationalStandingOrderConsentSystemTooManyRequests struct {
	Payload *models.Error
}

// IsSuccess returns true when this get international standing order consent system too many requests response has a 2xx status code
func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get international standing order consent system too many requests response has a 3xx status code
func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get international standing order consent system too many requests response has a 4xx status code
func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) IsClientError() bool {
	return true
}

// IsServerError returns true when this get international standing order consent system too many requests response has a 5xx status code
func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) IsServerError() bool {
	return false
}

// IsCode returns true when this get international standing order consent system too many requests response a status code equal to that given
func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) IsCode(code int) bool {
	return code == 429
}

// Code gets the status code for the get international standing order consent system too many requests response
func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) Code() int {
	return 429
}

func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemTooManyRequests %s", 429, payload)
}

func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /open-banking/international-standing-order-consent/{login}][%d] getInternationalStandingOrderConsentSystemTooManyRequests %s", 429, payload)
}

func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetInternationalStandingOrderConsentSystemTooManyRequests) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
